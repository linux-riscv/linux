// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Transaction Manager
 *
 * Dedicated kthread that dequeues command messages, builds VCQs in
 * DMA queue slots, and rings the MBX doorbell.
 *
 * Command flow:
 *   1. Caller posts command_msg via cmh_tm_post_command()
 *   2. TM thread wakes, dequeues msg from CMQ
 *   3. Selects mailbox (core-to-MBX affinity, or caller-pinned)
 *   4. Copies pre-built VCQ entries into DMA slot at tail
 *   5. Creates transaction_obj, appends to per-MBX txn queue
 *   6. Writes tail+1 -> R_MBX_QUEUE_TAIL (doorbell)
 *
 * The Response Handler (cmh_rh.c) walks per-MBX txn queues
 * when an IRQ fires and the head advances, firing completion callbacks.
 *
 * Transaction state machine
 * -------------------------
 * Each async transaction moves through the following states.  DMA
 * buffers remain mapped and owned by the HW until the COMPLETE state
 * is reached -- only then are they safe to unmap/free.
 *
 *   QUEUED --[TM posts to HW]--> INFLIGHT
 *   (cmq)   |                       |      \
 *          |                       |       \--[timer fires]-->
 *          |                       |            TIMED_OUT
 *          |                       |               |
 *          |                  [HW completes /   [HW completes /
 *          |                   RH pops txn]      RH pops txn]
 *          |                       |               |
 *          |                       v               v
 *          |                    COMPLETE        COMPLETE
 *          |                   (err=HW rc)    (err=-ETIMEDOUT)
 *          |
 *          +--[pre-submit fail]--> freed (callback never fires)
 *
 * Note: QUEUED is the command_msg phase (sitting in the CMQ list,
 * not yet a transaction_obj).  The transaction_obj states tracked
 * by atomic_cmpxchg are INFLIGHT, TIMED_OUT, and COMPLETE only.
 *
 * Completion callback context guarantee:
 *   The crypto_request_complete() callback is invoked from one of:
 *     - The RH threaded IRQ handler (process context, BH disabled)
 *     - The watchdog timer (softirq / timer context)
 *     - The TM kthread during queue drain/cleanup (process context)
 *
 *   It is NEVER invoked from hardirq context.
 *
 *   The watchdog path runs from timer softirq because it must recover
 *   missed IRQs without sleeping.  This is crypto-API-compliant:
 *   crypto_request_complete() is documented safe from any context
 *   (including softirq).  Callers must NOT assume process context in
 *   their completion callbacks -- all operations therein must be
 *   softirq-safe (no mutex, no GFP_KERNEL, no sleeping locks).
 *
 *   For backlog promotion (-EINPROGRESS callbacks), the callback runs
 *   under the CMQ spinlock with IRQs disabled -- callers must handle
 *   this per the crypto API backlog contract.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/string.h>
#include <linux/completion.h>
#include <linux/overflow.h>
#include <linux/refcount.h>

#include "cmh_txn.h"
#include "cmh_rh.h"
#include "cmh_registers.h"
#include "cmh_config.h"
#include "cmh_vcq.h"
#include "cmh_debugfs.h"
#include "cmh_dma.h"

/* Module State */

static struct {
	struct cmh_config      *cfg;
	struct task_struct     *thread;
	bool                    running;

	/* Command Message Queue (CMQ) */
	struct list_head        cmq;
	spinlock_t              cmq_lock;   /* protects cmq + backlog lists */
	wait_queue_head_t       cmq_waitq;

	/* Backlog queue for CRYPTO_TFM_REQ_MAY_BACKLOG requests */
	struct list_head        backlog;
	u32                     backlog_depth;

	/* Per-mailbox transaction queues */
	struct cmh_mbx_txq     *txqs;       /* array[cfg->mbx_count] */

	/* Round-robin mailbox selector */
	u32                     next_mbx;
} tm;

static unsigned int cmq_max_depth = 256;
module_param(cmq_max_depth, uint, 0444);
MODULE_PARM_DESC(cmq_max_depth,
		 "Max pending commands in the Command Message Queue (default: 256)");

static unsigned int backlog_max_depth = 1024;
module_param(backlog_max_depth, uint, 0444);
MODULE_PARM_DESC(backlog_max_depth,
		 "Max pending commands in the backlog queue (0 = disable backlog, default: 1024)");

static unsigned int async_timeout_ms = 2000;

#define CMH_TM_BACKOFF_MIN_US   100  /* queue-full backoff range (us) */
#define CMH_TM_BACKOFF_MAX_US   500
static unsigned int cmq_depth;       /* current CMQ depth, protected by tm.cmq_lock */

/*
 * Monotonically increasing counter bumped by cmh_tm_txq_completion_notify().
 * Used as a generation check in the queue-full backoff predicate so that
 * wait_event_interruptible_timeout() returns immediately when a TXQ
 * completion frees a slot, rather than sleeping for the full timeout.
 */
static atomic_t txq_completion_gen;

/* -- Debugfs stat helpers (avoid anonymous compound blocks) ------------- */

static void cmh_stat_inc_mbx_queue_full(u32 mbx_idx)
{
	struct cmh_mbx_stats *s = cmh_debugfs_mbx_stats(mbx_idx);

	if (s)
		atomic64_inc(&s->queue_full_count);
}

static void cmh_stat_record_vcq_submit(u32 mbx_idx, u32 num_vcqs, u32 depth)
{
	struct cmh_mbx_stats *s = cmh_debugfs_mbx_stats(mbx_idx);

	if (s) {
		atomic64_add(num_vcqs, &s->vcqs_submitted);
		cmh_stat_update_max(&s->max_queue_depth, (s64)depth);
	}
}

static void cmh_stat_inc_tm_backoff(void)
{
	struct cmh_tm_stats *s = cmh_debugfs_tm_stats();

	if (s)
		atomic64_inc(&s->backoff_count);
}

static void cmh_stat_inc_cmq_eagain(void)
{
	struct cmh_tm_stats *s = cmh_debugfs_tm_stats();

	if (s)
		atomic64_inc(&s->cmq_eagain_count);
}

static void cmh_stat_record_cmq_post(u32 depth)
{
	struct cmh_tm_stats *s = cmh_debugfs_tm_stats();

	if (s) {
		atomic64_inc(&s->cmq_posts);
		cmh_stat_update_max(&s->cmq_depth_max, (s64)depth);
	}
}

static void cmh_stat_inc_async_timeout(void)
{
	struct cmh_tm_stats *s = cmh_debugfs_tm_stats();

	if (s)
		atomic64_inc(&s->async_timeout_count);
}

/*
 * Drop one reference on a command_msg; free when the last ref is dropped.
 * Used by cmh_tm_submit_sync() to share msg ownership between the
 * waiter (caller) and the TM subsystem (thread or cleanup drain).
 */
static void command_msg_put(struct command_msg *msg)
{
	if (refcount_dec_and_test(&msg->refs)) {
		kfree(msg->vcq_data);
		kfree(msg);
	}
}

/*
 * Drop one reference on a transaction_obj; free when the last ref drops.
 * Two references are held when the per-request timeout timer is armed:
 * one for the TXQ owner (RH/cleanup), one for the timer callback.
 * When no timer is armed, only the owner ref exists.
 */
static void txn_put(struct transaction_obj *txn)
{
	if (refcount_dec_and_test(&txn->refs))
		kfree(txn);
}

/*
 * Per-request async timeout callback (runs in softirq / timer context).
 *
 * This function ONLY marks the transaction state as TIMED_OUT via
 * atomic cmpxchg and drops the timer reference.  It does NOT fire
 * the completion callback, does NOT touch DMA buffers, and does NOT
 * write any MBX registers.
 *
 * Rationale: the HW may still be writing to DMA buffers at this
 * point.  Unmapping or freeing them here would be a use-after-free.
 * The actual -ETIMEDOUT completion fires later, from process
 * context, when the RH threaded IRQ pops the transaction after the
 * HW finishes (or after MBX abort/drain on rmmod/suspend).
 *
 * MBX_COMMAND_ABORT is NOT issued here.  It is issued by the RH
 * watchdog abort-stall detector under rh_process_lock, which
 * serialises it against RESTART/FLUSH recovery commands.  Writing
 * ABORT from timer softirq without the lock caused a race where
 * concurrent timeouts clobbered an in-progress RESTART, wedging
 * the mailbox.
 *
 * Context: softirq (timer).  Must not sleep.
 */
static void txn_timeout_fn(struct timer_list *t)
{
	struct transaction_obj *txn = timer_container_of(txn, t, timeout_timer);
	int old;

	old = atomic_cmpxchg(&txn->state, TXN_INFLIGHT, TXN_TIMED_OUT);
	if (old == TXN_INFLIGHT) {
		dev_err_ratelimited(cmh_dev(),
				    "tm: async timeout vcq=%u..%u mbx=%u cmd_id=0x%08x\n",
				    txn->first_vcq_id,
				    txn->last_vcq_id, txn->mailbox_idx,
				    txn->command_id);
		cmh_stat_inc_async_timeout();
	}

	txn_put(txn); /* drop timer ref */
}

/**
 * cmh_txn_finish() - Complete a popped transaction with FSM + timer cleanup
 * @txn: Transaction object to complete
 * @error: Error code from HW (0 on success)
 *
 * Three cases:
 *   1. Normal: state INFLIGHT -> COMPLETE.  Fire callback with HW error.
 *   2. Timed out: state already TXN_TIMED_OUT (timer marked it).
 *      Fire callback with -ETIMEDOUT.  DMA is now safe because the
 *      HW has finished and HEAD has advanced past this VCQ.
 *   3. Force-cancel (drain/quiesce): handled by caller, not here.
 */
void cmh_txn_finish(struct transaction_obj *txn, int error)
{
	int old;

	old = atomic_cmpxchg(&txn->state, TXN_INFLIGHT, TXN_COMPLETE);

	/* Dequeue the timer if still pending; drop timer ref if we did */
	if (timer_delete(&txn->timeout_timer))
		txn_put(txn);

	if (old == TXN_INFLIGHT) {
		/* HW completion (may carry error) */
		if (txn->complete)
			txn->complete(txn->completion_data, error);
	} else if (old == TXN_TIMED_OUT) {
		/* Timer won earlier; now HW is done -- deliver -ETIMEDOUT */
		if (txn->complete)
			txn->complete(txn->completion_data, -ETIMEDOUT);
	}

	txn_put(txn); /* drop owner ref */
}

/* Mailbox Slot Addressing */

/*
 * Return a kernel-virtual pointer to the VCQ slot for the given vcqid.
 * Mirrors CMH eSW's mbx_queue_addr() but uses the kernel virt_addr.
 */
static void *mbx_slot_ptr(struct cmh_mbx_config *mbx, u32 vcqid)
{
	u32 slot_mask = (1U << mbx->slots_log2) - 1U;
	u32 slot_offset = (vcqid & slot_mask) << mbx->stride_log2;

	return (u8 *)mbx->virt_addr + slot_offset;
}

/*
 * Return the number of free slots in a mailbox queue.
 */
static u32 mbx_free_slots(struct cmh_mbx_config *mbx)
{
	u32 head = cmh_reg_read32(mbx->reg_base, R_MBX_QUEUE_HEAD);
	u32 tail = cmh_reg_read32(mbx->reg_base, R_MBX_QUEUE_TAIL);
	u32 size = 1U << mbx->slots_log2;

	return size - (u32)(tail - head);
}

/**
 * cmh_tm_max_cmds_per_vcq() - Return max commands per VCQ slot
 *
 * Scans all mailbox configurations and returns the minimum number of
 * VCQ command entries that fit in a single slot, clamped to the
 * MIN_VCQ_CMDS..MAX_VCQ_CMDS range.
 *
 * Return: Maximum usable VCQ command count per slot.
 */
u32 cmh_tm_max_cmds_per_vcq(void)
{
	u32 i, min_cmds = MAX_VCQ_CMDS;

	for (i = 0; i < tm.cfg->mbx_count; i++) {
		u32 stride = 1U << tm.cfg->mailboxes[i].stride_log2;
		u32 cmds = stride / (u32)sizeof(struct vcq_cmd);

		if (cmds < min_cmds)
			min_cmds = cmds;
	}

	if (min_cmds < MIN_VCQ_CMDS)
		min_cmds = MIN_VCQ_CMDS;

	return min_cmds;
}

/**
 * cmh_tm_mbx_count() - Return the number of configured mailboxes
 *
 * Return: Number of mailboxes in the current configuration.
 */
u32 cmh_tm_mbx_count(void)
{
	return tm.cfg->mbx_count;
}

/* Core-to-MBX Affinity -- Config-Driven Multi-Instance Support */

/*
 * Per-core-type configuration table.  Each entry holds one or more
 * (core_id, mbx_idx) instances.  Defaults: single instance per core
 * type with the standard CORE_ID_* and MBX auto-assigned on first use
 * (mbx_idx = -1).  Module params can override for explicit assignment
 * and multi-instance support.
 *
 * Round-robin across instances for each new crypto operation.
 */

struct core_instance_info {
	u32		core_id;	/* VCQ dispatch core_id */
	/*
	 * Assigned MBX index, or -1 (sentinel) for auto-assign on first
	 * use.  Uses atomic_t for a lockless once-only latch: the first
	 * caller does atomic_cmpxchg(&mbx_idx, -1, new_mbx); all later
	 * callers see the winning value via atomic_read().
	 */
	atomic_t	mbx_idx;
};

struct core_type_info {
	u32		num_instances;
	struct core_instance_info instances[CMH_MAX_CORE_INSTANCES];
	atomic_t	next_instance;	/* round-robin counter */
};

static struct core_type_info core_types[CMH_NUM_CORE_TYPES] = {
	[CMH_CORE_HC]  = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_HC,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_AES] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_AES,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_SM4] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_SM4,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_SM3] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_SM3,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_CCP] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_CCP,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_PKE] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_PKE,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_QSE] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_QSE,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
	[CMH_CORE_HCQ] = { .num_instances = 1,
	  .instances = { { .core_id = CORE_ID_HCQ,
			   .mbx_idx = ATOMIC_INIT(-1) } } },
};

/* Round-robin counter for auto-assigning MBXes to core instances */
static atomic_t affinity_next_mbx = ATOMIC_INIT(0);

/**
 * cmh_tm_affinity_reset() - Reset core-to-MBX affinity state
 *
 * Clears all auto-assigned MBX bindings and resets round-robin
 * counters for both the global MBX allocator and per-core-type
 * instance selectors.
 */
void cmh_tm_affinity_reset(void)
{
	u32 i, j;

	atomic_set(&affinity_next_mbx, 0);

	/* Reset multi-instance table */
	for (i = 0; i < CMH_NUM_CORE_TYPES; i++) {
		struct core_type_info *ct = &core_types[i];

		atomic_set(&ct->next_instance, 0);
		for (j = 0; j < ct->num_instances; j++)
			atomic_set(&ct->instances[j].mbx_idx, -1);
	}
}

/**
 * cmh_core_default_id() - Return default core_id for a core type
 * @type: Core type selector
 *
 * Returns the first-instance core_id for @type without advancing the
 * round-robin counter.  Used by callers pinned to a fixed MBX (e.g.
 * mgmt ioctls on MGMT_MBX) that only need the VCQ core_id field.
 *
 * Return: VCQ core_id value for the default instance of @type.
 */
u32 cmh_core_default_id(enum cmh_core_type type)
{
	if (WARN_ON_ONCE(type >= CMH_NUM_CORE_TYPES))
		return 0;

	return core_types[type].instances[0].core_id;
}

/**
 * cmh_core_select_instance() - Select a core instance via round-robin
 * @type: Core type selector
 *
 * Round-robin across configured instances, each permanently pinned to
 * its MBX (auto-assigned on first use if mbx_idx was -1).
 *
 * Uses atomic_inc_return (pre-increment), so the very first call for a
 * given type returns instance[1 % N].  Over the lifetime of the module
 * the distribution is perfectly balanced; the off-by-one only affects
 * the first cycle.
 *
 * The (u32) cast before the modulo ensures correct behaviour across
 * the INT_MAX -> INT_MIN wraparound of atomic_t: (u32)INT_MIN =
 * 0x80000000, and 0x80000000 % N still yields a valid index.
 *
 * Return: A core_dispatch with (core_id, mbx_idx) for the selected
 *         instance.
 */
struct core_dispatch cmh_core_select_instance(enum cmh_core_type type)
{
	struct core_type_info *ct;
	struct core_instance_info *inst;
	struct core_dispatch d;
	u32 idx, count;
	s32 mbx, new_mbx, old;

	if (WARN_ON_ONCE(type >= CMH_NUM_CORE_TYPES))
		return (struct core_dispatch){ .core_id = 0, .mbx_idx = -1 };

	ct = &core_types[type];
	idx = (u32)atomic_inc_return(&ct->next_instance) % ct->num_instances;
	inst = &ct->instances[idx];

	d.core_id = inst->core_id;

	mbx = atomic_read(&inst->mbx_idx);
	if (mbx >= 0) {
		d.mbx_idx = mbx;
		return d;
	}

	/* Auto-assign on first use */
	count = tm.cfg->mbx_count;
	new_mbx = (s32)((u32)atomic_inc_return(&affinity_next_mbx) % count);
	old = atomic_cmpxchg(&inst->mbx_idx, -1, new_mbx);

	if (old >= 0) {
		d.mbx_idx = old;
	} else {
		d.mbx_idx = new_mbx;
		dev_info(cmh_dev(),
			 "tm: core 0x%02x -> mbx %d (auto)\n",
			 inst->core_id, new_mbx);
	}

	return d;
}

/**
 * cmh_core_num_instances() - Return instance count for a core type
 * @type: Core type selector
 *
 * Return: Number of configured instances for @type.
 */
u32 cmh_core_num_instances(enum cmh_core_type type)
{
	if (WARN_ON_ONCE(type >= CMH_NUM_CORE_TYPES))
		return 1;

	return core_types[type].num_instances;
}

/**
 * cmh_core_get_instance() - Get dispatch info for a specific instance
 * @type: Core type selector
 * @idx: Instance index within @type
 *
 * Returns (core_id, mbx_idx) for a specific instance by index,
 * without advancing the round-robin counter.  Triggers MBX auto-assign
 * on first use if the instance has no MBX yet.
 *
 * Return: A core_dispatch with (core_id, mbx_idx) for instance @idx.
 */
struct core_dispatch cmh_core_get_instance(enum cmh_core_type type, u32 idx)
{
	struct core_type_info *ct;
	struct core_instance_info *inst;
	struct core_dispatch d;
	u32 count;
	s32 mbx, new_mbx, old;

	if (WARN_ON_ONCE(type >= CMH_NUM_CORE_TYPES))
		return (struct core_dispatch){ .core_id = 0, .mbx_idx = -1 };

	ct = &core_types[type];
	if (WARN_ON_ONCE(idx >= ct->num_instances))
		return (struct core_dispatch){ .core_id = 0, .mbx_idx = -1 };

	inst = &ct->instances[idx];
	d.core_id = inst->core_id;

	mbx = atomic_read(&inst->mbx_idx);
	if (mbx >= 0) {
		d.mbx_idx = mbx;
		return d;
	}

	/* Auto-assign on first use */
	count = tm.cfg->mbx_count;
	new_mbx = (s32)((u32)atomic_inc_return(&affinity_next_mbx) % count);
	old = atomic_cmpxchg(&inst->mbx_idx, -1, new_mbx);

	if (old >= 0) {
		d.mbx_idx = old;
	} else {
		d.mbx_idx = new_mbx;
		dev_info(cmh_dev(),
			 "tm: core 0x%02x -> mbx %d (auto)\n",
			 inst->core_id, new_mbx);
	}

	return d;
}

/**
 * cmh_tm_txq_completion_notify() - Wake TM thread after RH completion
 *
 * Wakes the TM thread after the Response Handler completes a
 * transaction.  This unblocks the TM if it is waiting for a free MBX
 * slot.  The generation counter bump ensures the wait_event predicate
 * evaluates to true on the next check.
 */
void cmh_tm_txq_completion_notify(void)
{
	atomic_inc(&txq_completion_gen);
	wake_up_interruptible(&tm.cmq_waitq);
}

/* Mailbox Selection */

/*
 * Select a mailbox with at least @slots_needed free slots (round-robin).
 * Returns mailbox index, or -EAGAIN if no mailbox qualifies.
 *
 * Note: the free-slot check here is advisory -- actual slot availability
 * is enforced by the ring arithmetic under dispatch_lock in submit_vcq().
 * A TOCTOU gap exists between this check and the subsequent slot write,
 * but it is safe: the worst case is a spurious -EAGAIN / backoff, never
 * a ring overcommit.
 */
static int select_mailbox(u32 slots_needed)
{
	u32 count = tm.cfg->mbx_count;
	u32 start = tm.next_mbx;
	u32 i;

	for (i = 0; i < count; i++) {
		u32 idx = (start + i) % count;

		if (cmh_rh_mbx_is_wedged(idx))
			continue;

		if (mbx_free_slots(&tm.cfg->mailboxes[idx]) >= slots_needed) {
			tm.next_mbx = (idx + 1) % count;
			return (int)idx;
		}
		cmh_stat_inc_mbx_queue_full(idx);
	}

	return -EAGAIN;
}

/*
 * Resolve the target mailbox for a command message.
 *
 * If the message has a pinned MBX and it has enough free slots, use it.
 * Otherwise fall back to round-robin selection.  Returns mailbox index,
 * or -EAGAIN when no MBX has enough free slots or all are wedged.
 */
static int resolve_mbx(struct command_msg *msg)
{
	u32 slots = msg->num_vcqs > 0 ? msg->num_vcqs : 1;

	if (msg->target_mbx >= 0 &&
	    (u32)msg->target_mbx < tm.cfg->mbx_count) {
		if (cmh_rh_mbx_is_wedged((u32)msg->target_mbx))
			return -EAGAIN;
		if (mbx_free_slots(&tm.cfg->mailboxes[msg->target_mbx]) >=
		    slots)
			return msg->target_mbx;
		return -EAGAIN; /* pinned MBX full, retry */
	}

	return select_mailbox(slots);
}

/* VCQ Submission */

/*
 * Write VCQ(s) into consecutive DMA slots and ring the doorbell.
 *
 * A command_msg may carry one or more VCQs (num_vcqs field).  For a
 * multi-VCQ message the flat vcq_data array contains N VCQs laid out
 * contiguously, each starting with its own header whose cmds field
 * gives that VCQ's entry count.  All VCQs are written to consecutive
 * MBX slots and tracked by a single transaction_obj.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int submit_vcq(struct command_msg *msg, u32 mbx_idx)
{
	struct cmh_mbx_config *mbx = &tm.cfg->mailboxes[mbx_idx];
	struct cmh_mbx_txq *txq = &tm.txqs[mbx_idx];
	struct transaction_obj *txn;
	const struct vcq_cmd *cmds = msg->vcq_data;
	u32 num_vcqs = msg->num_vcqs > 0 ? msg->num_vcqs : 1;
	u32 tail, stride_bytes, offset = 0;
	unsigned long flags;
	u32 v;

	mutex_lock(&txq->dispatch_lock);

	/* Read current tail (first VCQ ID) */
	tail = cmh_reg_read32(mbx->reg_base, R_MBX_QUEUE_TAIL);
	stride_bytes = 1U << mbx->stride_log2;

	/* Allocate transaction tracking object */
	txn = kzalloc_obj(*txn, GFP_KERNEL);
	if (!txn) {
		mutex_unlock(&txq->dispatch_lock);
		return -ENOMEM;
	}

	/* Write each VCQ into a consecutive DMA slot */
	for (v = 0; v < num_vcqs; v++) {
		u32 vcq_cmds, copy_size;
		void *slot;

		/*
		 * For single-VCQ messages (backward compat) use the
		 * msg-level vcq_count.  For multi-VCQ, parse the per-VCQ
		 * header to find each VCQ's command count.
		 */
		if (num_vcqs == 1) {
			vcq_cmds = msg->vcq_count;
		} else {
			const struct vcq_hdr *hdr =
				(const struct vcq_hdr *)&cmds[offset].hwc;
			vcq_cmds = hdr->cmds;
		}

		copy_size = vcq_cmds * sizeof(struct vcq_cmd);
		if (copy_size > stride_bytes) {
			dev_err(cmh_dev(), "tm: VCQ %u too large (%u bytes > stride %u)\n",
				v, copy_size, stride_bytes);
			mutex_unlock(&txq->dispatch_lock);
			kfree(txn);
			return -EMSGSIZE;
		}

		if (vcq_cmds < MIN_VCQ_CMDS || vcq_cmds > MAX_VCQ_CMDS) {
			dev_err(cmh_dev(), "tm: invalid vcq_count %u (range %u..%u)\n",
				vcq_cmds, MIN_VCQ_CMDS, MAX_VCQ_CMDS);
			mutex_unlock(&txq->dispatch_lock);
			kfree(txn);
			return -EINVAL;
		}

		/* Copy pre-built VCQ into DMA slot */
		slot = mbx_slot_ptr(mbx, tail + v);
		cmh_dma_write(slot, &cmds[offset], copy_size);

		/* Zero remaining slot bytes to avoid stale data */
		if (copy_size < stride_bytes)
			cmh_dma_zero((u8 *)slot + copy_size,
				     stride_bytes - copy_size);

		offset += vcq_cmds;
	}

	/* Ensure VCQ data is visible in memory before advancing tail */
	wmb();
	/* FPGA: confirm DRAM accepted writes before SIC doorbell (cross-slave) */
	cmh_dma_fence(mbx_slot_ptr(mbx, tail + num_vcqs - 1));

	/* Fill in transaction spanning all VCQs */
	txn->first_vcq_id = tail;
	txn->last_vcq_id = tail + num_vcqs - 1;
	txn->mailbox_idx = mbx_idx;
	txn->command_id = msg->command_id;
	txn->error_code = 0;
	txn->complete = msg->complete;
	txn->completion_data = msg->completion_data;
	atomic_set(&txn->state, TXN_INFLIGHT);
	timer_setup(&txn->timeout_timer, txn_timeout_fn, 0);
	INIT_LIST_HEAD(&txn->list);

	/*
	 * Set refcount: 2 if a per-txn timer will be armed (one ref for
	 * the TXQ owner that pops it, one for the timer callback), or 1
	 * if no timer (sync paths, or async_timeout_ms == 0).
	 */
	if (msg->timeout_jiffies)
		refcount_set(&txn->refs, 2);
	else
		refcount_set(&txn->refs, 1);

	/* Enqueue transaction under spinlock */
	spin_lock_irqsave(&txq->lock, flags);
	list_add_tail(&txn->list, &txq->head);
	txq->depth++;
	spin_unlock_irqrestore(&txq->lock, flags);

	/* Ring doorbell: advance tail by number of VCQs submitted */
	cmh_reg_write32(tail + num_vcqs, mbx->reg_base, R_MBX_QUEUE_TAIL);

	/* Arm per-request timeout after doorbell (async only) */
	if (msg->timeout_jiffies)
		mod_timer(&txn->timeout_timer,
			  jiffies + msg->timeout_jiffies);

	mutex_unlock(&txq->dispatch_lock);

	cmh_stat_record_vcq_submit(mbx_idx, num_vcqs, txq->depth);

	dev_dbg(cmh_dev(), "tm: submitted %u vcq(s) id=%u..%u to mbx[%u] tail_now=%u\n",
		num_vcqs, tail, tail + num_vcqs - 1, mbx_idx,
		 tail + num_vcqs);

	return 0;
}

/* TM Thread */

static int cmh_tm_thread(void *data)
{
	struct command_msg *msg;
	unsigned long flags;
	int mbx_idx, ret;

	dev_info(cmh_dev(), "tm: thread started\n");

	while (!kthread_should_stop()) {
		/* Wait for work or stop signal */
		wait_event_interruptible(tm.cmq_waitq,
					 !list_empty(&tm.cmq) || kthread_should_stop());

		if (kthread_should_stop())
			break;

		/* Dequeue one command message */
		spin_lock_irqsave(&tm.cmq_lock, flags);
		if (list_empty(&tm.cmq)) {
			spin_unlock_irqrestore(&tm.cmq_lock, flags);
			continue;
		}
		msg = list_first_entry(&tm.cmq, struct command_msg, list);
		list_del_init(&msg->list);
		cmq_depth--;

		/*
		 * Promote one backlogged request into the CMQ now that
		 * there is room.  Notify the crypto consumer with
		 * -EINPROGRESS so it knows the request has left backlog.
		 */
		if (!list_empty(&tm.backlog)) {
			struct command_msg *bl;

			bl = list_first_entry(&tm.backlog,
					      struct command_msg, list);
			list_move_tail(&bl->list, &tm.cmq);
			tm.backlog_depth--;
			cmq_depth++;
			cmh_stat_record_cmq_post(cmq_depth);
			/*
			 * Signal -EINPROGRESS while still under cmq_lock
			 * so the consumer sees it before the final
			 * completion.  The callback must be IRQ-safe
			 * (required by the async contract anyway).
			 */
			if (bl->complete)
				bl->complete(bl->completion_data,
					     -EINPROGRESS);
		}

		spin_unlock_irqrestore(&tm.cmq_lock, flags);

		/* Select a mailbox: pinned or round-robin */
		mbx_idx = resolve_mbx(msg);

		if (mbx_idx < 0) {
			/*
			 * Queue full -- re-enqueue at front and wait.
			 *
			 * Sleep on cmq_waitq with a short timeout.  The RH
			 * calls cmh_tm_txq_completion_notify() after each
			 * completed transaction, which bumps the generation
			 * counter and wakes us immediately.  The timeout is
			 * a safety net for missed wakeups.
			 */
			int gen = atomic_read(&txq_completion_gen);
			unsigned long tmo;

			spin_lock_irqsave(&tm.cmq_lock, flags);
			list_add(&msg->list, &tm.cmq);
			cmq_depth++;
			spin_unlock_irqrestore(&tm.cmq_lock, flags);

			tmo = usecs_to_jiffies(CMH_TM_BACKOFF_MAX_US);
			wait_event_interruptible_timeout(tm.cmq_waitq,
							 kthread_should_stop() ||
							 atomic_read(&txq_completion_gen) != gen,
							 tmo ?: 1);
			cmh_stat_inc_tm_backoff();
			continue;
		}

		/* Submit VCQ to selected mailbox */
		WRITE_ONCE(msg->actual_mbx, mbx_idx);
		ret = submit_vcq(msg, mbx_idx);
		if (ret && msg->complete)
			msg->complete(msg->completion_data, ret);
		command_msg_put(msg);
	}

	dev_info(cmh_dev(), "tm: thread stopped\n");
	return 0;
}

/* Public Interface */

/**
 * cmh_tm_init() - Initialize the Transaction Manager subsystem
 * @cfg: Hardware configuration describing mailboxes and core types
 *
 * Allocates per-mailbox transaction queues, applies core-type
 * configuration, and starts the TM kthread.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_tm_init(struct cmh_config *cfg)
{
	u32 i, j;

	if (cmq_max_depth == 0) {
		dev_warn(cmh_dev(),
			 "tm: cmq_max_depth=0 invalid, clamping to 1\n");
		cmq_max_depth = 1;
	}

	tm.cfg = cfg;
	tm.next_mbx = 0;
	cmq_depth = 0;

	cmh_tm_affinity_reset();

	/* Apply per-core-type config from DT child nodes */
	for (i = 0; i < CMH_NUM_CORE_TYPES; i++) {
		struct cmh_core_type_cfg *src = &cfg->core_types[i];
		struct core_type_info *ct = &core_types[i];

		ct->num_instances = src->num_instances;
		for (j = 0; j < src->num_instances; j++) {
			ct->instances[j].core_id = src->core_ids[j];
			if (src->mbx[j] >= 0)
				atomic_set(&ct->instances[j].mbx_idx,
					   src->mbx[j]);
		}
	}

	/* Initialize CMQ and backlog */
	INIT_LIST_HEAD(&tm.cmq);
	INIT_LIST_HEAD(&tm.backlog);
	tm.backlog_depth = 0;
	spin_lock_init(&tm.cmq_lock);
	init_waitqueue_head(&tm.cmq_waitq);

	/* Allocate per-mailbox transaction queues */
	tm.txqs = kcalloc(cfg->mbx_count, sizeof(*tm.txqs), GFP_KERNEL);
	if (!tm.txqs)
		return -ENOMEM;

	for (i = 0; i < cfg->mbx_count; i++) {
		INIT_LIST_HEAD(&tm.txqs[i].head);
		spin_lock_init(&tm.txqs[i].lock);
		mutex_init(&tm.txqs[i].dispatch_lock);
		tm.txqs[i].depth = 0;
	}

	/* Start TM thread */
	tm.thread = kthread_run(cmh_tm_thread, NULL, "cmh_tm");
	if (IS_ERR(tm.thread)) {
		int ret = PTR_ERR(tm.thread);

		dev_err(cmh_dev(), "tm: failed to start thread (rc=%d)\n", ret);
		tm.thread = NULL;
		kfree(tm.txqs);
		tm.txqs = NULL;
		return ret;
	}

	WRITE_ONCE(tm.running, true);
	dev_info(cmh_dev(),
		 "tm: initialized (%u mailboxes, cmq_depth=%u backlog=%u)\n",
		 cfg->mbx_count, cmq_max_depth, backlog_max_depth);

	return 0;
}

/*
 * cmh_tm_stop_and_drain_cmq() - Stop TM thread and drain CMQ/backlog
 *
 * Shared preamble for cmh_tm_cleanup() and cmh_tm_quiesce(): stops the
 * kthread, marks the TM as not running, then splices the CMQ and backlog
 * to local lists and cancels every pending command_msg outside the lock.
 */
static void cmh_tm_stop_and_drain_cmq(void)
{
	struct command_msg *msg, *tmp_msg;
	unsigned long flags;
	LIST_HEAD(cmq_drain);
	LIST_HEAD(backlog_drain);

	if (tm.thread) {
		kthread_stop(tm.thread);
		tm.thread = NULL;
	}
	WRITE_ONCE(tm.running, false);

	spin_lock_irqsave(&tm.cmq_lock, flags);
	list_splice_init(&tm.cmq, &cmq_drain);
	cmq_depth = 0;
	list_splice_init(&tm.backlog, &backlog_drain);
	tm.backlog_depth = 0;
	spin_unlock_irqrestore(&tm.cmq_lock, flags);

	list_for_each_entry_safe(msg, tmp_msg, &cmq_drain, list) {
		list_del(&msg->list);
		if (msg->complete)
			msg->complete(msg->completion_data, -ECANCELED);
		command_msg_put(msg);
	}
	list_for_each_entry_safe(msg, tmp_msg, &backlog_drain, list) {
		list_del(&msg->list);
		if (msg->complete)
			msg->complete(msg->completion_data, -ECANCELED);
		command_msg_put(msg);
	}
}

/**
 * cmh_tm_cleanup() - Tear down the Transaction Manager subsystem
 *
 * Stops the TM kthread, drains the CMQ, backlog, and all per-mailbox
 * transaction queues, notifying waiters with -ECANCELED or -ETIMEDOUT.
 * Frees all TM-owned resources.
 */
void cmh_tm_cleanup(void)
{
	struct transaction_obj *txn, *tmp_txn;
	unsigned long flags;
	u32 i;

	cmh_tm_stop_and_drain_cmq();

	/* Drain per-mailbox transaction queues */
	if (tm.txqs) {
		for (i = 0; i < tm.cfg->mbx_count; i++) {
			LIST_HEAD(drain);
			int old;

			spin_lock_irqsave(&tm.txqs[i].lock, flags);
			list_splice_init(&tm.txqs[i].head, &drain);
			tm.txqs[i].depth = 0;
			spin_unlock_irqrestore(&tm.txqs[i].lock, flags);

			list_for_each_entry_safe(txn, tmp_txn, &drain, list) {
				list_del(&txn->list);

				if (timer_delete_sync(&txn->timeout_timer))
					txn_put(txn);

				old = atomic_cmpxchg(&txn->state,
						     TXN_INFLIGHT,
						     TXN_COMPLETE);
				if (txn->complete) {
					if (old == TXN_INFLIGHT)
						txn->complete(txn->completion_data,
							      -ECANCELED);
					else if (old == TXN_TIMED_OUT)
						txn->complete(txn->completion_data,
							      -ETIMEDOUT);
				}

				txn_put(txn);
			}
		}
		kfree(tm.txqs);
		tm.txqs = NULL;
	}

	dev_info(cmh_dev(), "tm: cleaned up\n");
}

/*
 * Default drain timeout for suspend/quiesce (milliseconds).
 * Covers all symmetric + PKE operations.  PQC callers (SLH-DSA sign
 * at up to 120 s) should complete before system suspend is requested.
 */
static unsigned int drain_timeout_ms = 10000;

/**
 * cmh_tm_quiesce() - Quiesce the TM for suspend or shutdown
 *
 * Stops the TM kthread, drains the CMQ and backlog, then waits up to
 * drain_timeout_ms for in-flight transactions to complete via the
 * Response Handler.  Any remaining transactions after the deadline
 * are force-cancelled.
 */
void cmh_tm_quiesce(void)
{
	struct transaction_obj *txn, *tmp_txn;
	unsigned long deadline;
	unsigned long flags;
	u32 i;
	bool drained = true;

	cmh_tm_stop_and_drain_cmq();

	/* Wait for in-flight TXQ transactions to complete via RH */
	if (!tm.txqs)
		goto out;

	deadline = jiffies + msecs_to_jiffies(drain_timeout_ms);
	do {
		drained = true;
		for (i = 0; i < tm.cfg->mbx_count; i++) {
			if (READ_ONCE(tm.txqs[i].depth)) {
				drained = false;
				break;
			}
		}
		if (drained)
			break;
		usleep_range(1000, 2000);
	} while (time_before(jiffies, deadline));

	if (!drained) {
		dev_warn(cmh_dev(),
			 "tm: quiesce drain timeout (%u ms), cancelling remaining transactions\n",
			 drain_timeout_ms);
		for (i = 0; i < tm.cfg->mbx_count; i++) {
			LIST_HEAD(drain);
			int old;

			spin_lock_irqsave(&tm.txqs[i].lock, flags);
			list_splice_init(&tm.txqs[i].head, &drain);
			tm.txqs[i].depth = 0;
			spin_unlock_irqrestore(&tm.txqs[i].lock, flags);

			list_for_each_entry_safe(txn, tmp_txn, &drain, list) {
				list_del(&txn->list);

				if (timer_delete_sync(&txn->timeout_timer))
					txn_put(txn);

				old = atomic_cmpxchg(&txn->state,
						     TXN_INFLIGHT,
						     TXN_COMPLETE);
				if (txn->complete) {
					if (old == TXN_INFLIGHT)
						txn->complete(txn->completion_data,
							      -ECANCELED);
					else if (old == TXN_TIMED_OUT)
						txn->complete(txn->completion_data,
							      -ETIMEDOUT);
				}

				txn_put(txn);
			}
		}
	}

out:
	dev_info(cmh_dev(), "tm: quiesced%s\n",
		 drained ? "" : " (forced)");
}

/**
 * cmh_tm_resume() - Resume the TM after suspend
 *
 * Restarts the TM kthread after a prior cmh_tm_quiesce().
 *
 * Return: 0 on success, negative errno if kthread creation fails.
 */
int cmh_tm_resume(void)
{
	if (tm.thread || !tm.cfg)
		return 0;

	tm.thread = kthread_run(cmh_tm_thread, NULL, "cmh_tm");
	if (IS_ERR(tm.thread)) {
		int ret = PTR_ERR(tm.thread);

		dev_err(cmh_dev(), "tm: resume kthread_run failed (%d)\n",
			ret);
		tm.thread = NULL;
		return ret;
	}
	WRITE_ONCE(tm.running, true);
	dev_info(cmh_dev(), "tm: resumed\n");
	return 0;
}

/**
 * cmh_tm_try_cancel_command() - Cancel a queued command message
 * @msg: Command message to cancel
 *
 * Attempts to remove @msg from the CMQ before the TM thread dequeues
 * it.  Must be called while @msg is still valid (before the caller's
 * stack frame that owns it is freed).
 *
 * Return: true if @msg was removed, false if already consumed by TM.
 */
bool cmh_tm_try_cancel_command(struct command_msg *msg)
{
	unsigned long flags;
	bool cancelled = false;

	spin_lock_irqsave(&tm.cmq_lock, flags);
	if (!list_empty(&msg->list)) {
		list_del_init(&msg->list);
		cmq_depth--;
		cancelled = true;
	}
	spin_unlock_irqrestore(&tm.cmq_lock, flags);

	return cancelled;
}

/**
 * cmh_tm_post_command() - Post a command message to the CMQ
 * @msg: Pre-built command message to enqueue
 *
 * Enqueues @msg on the Command Message Queue and wakes the TM thread.
 * If the CMQ is full, the message may be placed on the backlog queue
 * (returning -EBUSY) if @msg->backlog_ok is set, or rejected with
 * -EAGAIN.
 *
 * Return: 0 on success, -EBUSY if backlogged, -EAGAIN if full,
 *         -ENODEV if TM is not running.
 */
int cmh_tm_post_command(struct command_msg *msg)
{
	unsigned long flags;

	if (!READ_ONCE(tm.running))
		return -ENODEV;

	spin_lock_irqsave(&tm.cmq_lock, flags);
	if (cmq_depth >= cmq_max_depth) {
		if (msg->backlog_ok &&
		    tm.backlog_depth < backlog_max_depth) {
			list_add_tail(&msg->list, &tm.backlog);
			tm.backlog_depth++;
			spin_unlock_irqrestore(&tm.cmq_lock, flags);
			return -EBUSY;
		}
		spin_unlock_irqrestore(&tm.cmq_lock, flags);
		cmh_stat_inc_cmq_eagain();
		return -EAGAIN;
	}
	INIT_LIST_HEAD(&msg->list);
	list_add_tail(&msg->list, &tm.cmq);
	cmq_depth++;
	cmh_stat_record_cmq_post(cmq_depth);
	spin_unlock_irqrestore(&tm.cmq_lock, flags);

	wake_up_interruptible(&tm.cmq_waitq);
	return 0;
}

/* Synchronous Submit (refcounted completion + timeout) */

/*
 * Heap-allocated sync context with refcounting.
 *
 * The completion callback may fire after the waiter has timed out and
 * returned (e.g. during cmh_tm_cleanup on rmmod).  If the struct lived
 * on the waiter's stack, the callback would touch freed memory --
 * triggering a "BUG: spinlock bad magic" on the completion's spinlock.
 *
 * Two references are held: one by the waiter, one by the callback.
 * Whichever runs last frees the struct.
 */
struct cmh_sync_ctx {
	struct completion   done;
	int                 error;
	refcount_t          refs;   /* 2: waiter + callback */

	/* Optional orphan cleanup -- called when the last ref drops after
	 * the waiter abandoned an in-flight VCQ (noabort path).  Lets the
	 * caller defer DMA-buffer cleanup until the eSW finishes writing.
	 */
	void (*orphan_cb)(void *data);
	void *orphan_data;
};

static void cmh_sync_ctx_put(struct cmh_sync_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->refs)) {
		if (ctx->orphan_cb)
			ctx->orphan_cb(ctx->orphan_data);
		kfree(ctx);
	}
}

static void cmh_sync_complete(void *data, int error)
{
	struct cmh_sync_ctx *ctx = data;

	ctx->error = error;
	complete(&ctx->done);
	cmh_sync_ctx_put(ctx);
}

/*
 * Default VCQ completion timeout (milliseconds), tunable via debugfs
 * config/vcq_timeout_ms.  Only affects the default timeout used by cmh_tm_submit_sync()
 * and cmh_tm_submit_sync_mbx(); callers that pass an explicit timeout_hz
 * (e.g. RSA keygen) are not affected.
 */
static unsigned int vcq_timeout_ms = 2000;

/*
 * Extended timeout for slow crypto operations: RSA keygen, PQC
 * keygen/sign/verify.  Tunable via debugfs config/slow_op_timeout_ms.
 */
static unsigned int slow_op_timeout_ms = 300000;

/**
 * cmh_tm_submit_sync_tmo() - Synchronous VCQ submit with timeout
 * @vcq_cmds: Array of pre-built VCQ command entries
 * @vcq_count: Total number of entries in @vcq_cmds
 * @num_vcqs: Number of VCQs packed in @vcq_cmds
 * @target_mbx: Pinned mailbox index, or -1 for round-robin
 * @timeout_hz: Completion timeout in jiffies
 *
 * Posts a VCQ command to the TM, waits for completion up to
 * @timeout_hz.  On timeout, issues MBX_COMMAND_ABORT if the VCQ is
 * already in-flight.  Must be called from process context.
 *
 * Return: 0 on success, -ETIMEDOUT, or negative errno.
 */
int cmh_tm_submit_sync_tmo(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			   u32 num_vcqs, s32 target_mbx,
			   unsigned long timeout_hz)
{
	struct cmh_sync_ctx *sync;
	struct command_msg *msg;
	unsigned long left;
	int ret;

	/*
	 * This path sleeps (GFP_KERNEL allocations + wait_for_completion)
	 * and is not safe from atomic / non-sleepable contexts.  All
	 * current callers run in process context (crypto API userspace or
	 * ioctl), so this is never violated today.  Catch it loudly if
	 * a future caller gets this wrong.
	 */
	WARN_ON_ONCE(!in_task());

	sync = kzalloc_obj(*sync, GFP_KERNEL);
	if (!sync)
		return -ENOMEM;

	msg = kzalloc_obj(*msg, GFP_KERNEL);
	if (!msg) {
		kfree(sync);
		return -ENOMEM;
	}

	init_completion(&sync->done);
	sync->error = 0;
	refcount_set(&sync->refs, 2);  /* waiter + callback */

	/*
	 * Heap-copy the caller's VCQ array so the msg owns its data.
	 * This decouples VCQ lifetime from the caller's stack frame,
	 * which matters when the TM thread backs off (resolve_mbx
	 * returns -1) and re-enqueues the msg after the caller's
	 * wait_for_completion_timeout expires.
	 */
	msg->vcq_data = kmemdup(vcq_cmds, vcq_count * sizeof(*vcq_cmds),
				GFP_KERNEL);
	if (!msg->vcq_data) {
		kfree(msg);
		kfree(sync);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&msg->list);
	if (WARN_ON_ONCE(vcq_count < MIN_VCQ_CMDS)) {
		ret = -EINVAL;
		goto err_free;
	}
	msg->command_id = vcq_cmds[1].id;  /* first real command's ID */
	msg->vcq_count  = vcq_count;
	msg->num_vcqs   = num_vcqs;
	msg->target_mbx = target_mbx;
	msg->actual_mbx = -1;
	msg->complete   = cmh_sync_complete;
	msg->completion_data = sync;
	refcount_set(&msg->refs, 2);       /* waiter + TM subsystem */

	ret = cmh_tm_post_command(msg);
	if (ret) {
err_free:
		kfree(msg->vcq_data);
		kfree(msg);
		kfree(sync);  /* callback will never fire */
		return ret;
	}

	dev_dbg(cmh_dev(), "tm: submit_sync posted cmd 0x%08x, waiting...\n",
		msg->command_id);

	left = wait_for_completion_timeout(&sync->done, timeout_hz);
	if (!left) {
		dev_err(cmh_dev(),
			"tm: submit_sync timeout (%lums) cmd=0x%08x\n",
			timeout_hz * 1000 / HZ, msg->command_id);
		if (cmh_tm_try_cancel_command(msg)) {
			/*
			 * Msg was still queued -- TM never saw it.
			 * Drop the callback ref (no txn will fire it)
			 * and free msg directly (sole owner).
			 */
			cmh_sync_ctx_put(sync);  /* no txn -> drop cb ref */
			cmh_sync_ctx_put(sync);  /* drop waiter ref */
			command_msg_put(msg);    /* matches refcount_set(2) */
			command_msg_put(msg);
		} else {
			/*
			 * TM has dequeued msg and the VCQ is in-flight.
			 * Issue MBX_COMMAND_ABORT to force-stop the VCQ;
			 * the RH will fire MBX_ERROR_IRQ, complete the
			 * transaction with -EIO, and issue RESTART.
			 *
			 * cmh_rh_abort_mbx() serialises the write under
			 * rh_process_lock, preventing clobber of a
			 * concurrent RESTART/FLUSH from the watchdog.
			 */
			s32 abrt_mbx = READ_ONCE(msg->actual_mbx);

			if (abrt_mbx >= 0 &&
			    (u32)abrt_mbx < tm.cfg->mbx_count) {
				dev_warn(cmh_dev(),
					 "tm: aborting mbx[%d] cmd=0x%08x\n",
					 abrt_mbx, msg->command_id);
				cmh_rh_abort_mbx((u32)abrt_mbx);
			}

			/*
			 * Wait for the RH completion (ABORT triggers
			 * MBX_ERROR_IRQ within microseconds).  Fixed
			 * 5 s ceiling -- not configurable because if
			 * ABORT doesn't complete in this window the
			 * HW is wedged and more waiting won't help.
			 */
			left = wait_for_completion_timeout(&sync->done,
							   5 * HZ);
			if (!left) {
				/*
				 * ABORT did not complete within 5 s -- HW
				 * is wedged.  The eSW may still be writing
				 * to DMA buffers owned by the caller, so we
				 * cannot let the caller free them.  Transfer
				 * ownership to the sync_ctx orphan mechanism;
				 * the RH callback (if it ever fires) will
				 * free via orphan_cb.  If it never fires, the
				 * buffers leak -- acceptable for a wedged HW
				 * path that should never occur in practice.
				 */
				dev_err(cmh_dev(),
					"tm: abort timeout (5s) cmd=0x%08x - DMA buffers orphaned\n",
					msg->command_id);
			}
			cmh_sync_ctx_put(sync);  /* drop waiter ref */
			command_msg_put(msg);    /* drop waiter ref on msg */
		}
		return -ETIMEDOUT;
	}

	ret = sync->error;
	cmh_sync_ctx_put(sync);  /* drop waiter ref */
	command_msg_put(msg);    /* drop waiter ref on msg */
	return ret;
}

/**
 * cmh_tm_submit_sync_mbx() - Synchronous VCQ submit on a target MBX
 * @vcq_cmds: Array of pre-built VCQ command entries
 * @vcq_count: Total number of entries in @vcq_cmds
 * @num_vcqs: Number of VCQs packed in @vcq_cmds
 * @target_mbx: Pinned mailbox index, or -1 for round-robin
 *
 * Convenience wrapper around cmh_tm_submit_sync_tmo() using the
 * default vcq_timeout_ms module parameter.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_tm_submit_sync_mbx(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			   u32 num_vcqs, s32 target_mbx)
{
	return cmh_tm_submit_sync_tmo(vcq_cmds, vcq_count, num_vcqs,
				     target_mbx,
				     msecs_to_jiffies(vcq_timeout_ms));
}

/**
 * cmh_tm_async_timeout_jiffies() - Default async per-request timeout
 *
 * Return: Timeout in jiffies from the async_timeout_ms module param,
 *         or 0 if async timeouts are disabled.
 */
unsigned long cmh_tm_async_timeout_jiffies(void)
{
	return async_timeout_ms ? msecs_to_jiffies(async_timeout_ms) : 0;
}

/**
 * cmh_tm_slow_op_timeout_jiffies() - Timeout for slow crypto ops
 *
 * Returns the extended timeout used for RSA keygen, PQC keygen/sign,
 * and similar long-running operations.
 *
 * Return: Timeout in jiffies from the slow_op_timeout_ms module param.
 */
unsigned long cmh_tm_slow_op_timeout_jiffies(void)
{
	return msecs_to_jiffies(slow_op_timeout_ms);
}

/**
 * cmh_tm_submit_async() - Asynchronous VCQ submission
 * @vcq_cmds: Array of pre-built VCQ command entries
 * @vcq_count: Total number of entries in @vcq_cmds
 * @num_vcqs: Number of VCQs packed in @vcq_cmds
 * @target_mbx: Pinned mailbox index, or -1 for round-robin
 * @callback: Completion callback (see context note below)
 * @callback_data: Opaque data passed to @callback
 * @backlog_ok: Allow backlogging if CMQ is full
 * @timeout_jiffies: Per-request timeout (0 = no timeout)
 *
 * Builds a command_msg, heap-copies the VCQ data, and posts it to the
 * CMQ via cmh_tm_post_command().
 *
 * Callback context guarantee:
 *   The @callback may be invoked from one of:
 *   - RH threaded IRQ handler (process context, BH disabled)
 *   - RH watchdog timer (softirq / timer context)
 *   - TM kthread if submit_vcq() fails post-dequeue
 *   - cmh_tm_cleanup()/cmh_tm_quiesce() during drain (process context)
 *   It is NEVER invoked from hardirq context.
 *
 *   Because the watchdog path runs from timer softirq, callbacks
 *   MUST be safe in atomic/softirq context: no mutex, no GFP_KERNEL,
 *   no sleeping locks.  crypto_request_complete() is safe (documented
 *   callable from any context).  kfree_sensitive() and
 *   scatterwalk_map_and_copy() are also safe (non-sleeping).
 *   Callers must not assume thread affinity (callback may run on any CPU).
 *
 * Unlike the _sync variants, this function:
 *   - Does NOT allocate a cmh_sync_ctx or wait for completion
 *   - Uses GFP_ATOMIC for internal allocations because the crypto API
 *     may call ->encrypt/->decrypt/->hash_final from softirq context
 *     (e.g. network stack via IPsec/TLS); GFP_KERNEL would deadlock.
 *
 * The command_msg is single-owner (refcount 1) -- the TM subsystem
 * owns it after post and frees it after dispatching to the HW.
 *
 * DMA buffer ownership: the caller transfers ownership to the callback
 * on return of 0 or -EBUSY.  On any other return, the caller must
 * clean up DMA buffers itself -- the callback will never fire.
 *
 * Return: 0 on successful post, -EBUSY if backlogged, -ENOMEM,
 *         -EINVAL, -EAGAIN, or -ENODEV on failure.
 */
int cmh_tm_submit_async(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			u32 num_vcqs, s32 target_mbx,
			cmh_completion_fn callback, void *callback_data,
			bool backlog_ok, unsigned long timeout_jiffies)
{
	struct command_msg *msg;
	int ret;

	msg = kzalloc_obj(*msg, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	msg->vcq_data = kmemdup(vcq_cmds,
				array_size(vcq_count, sizeof(*vcq_cmds)),
				GFP_ATOMIC);
	if (!msg->vcq_data) {
		kfree(msg);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&msg->list);
	if (WARN_ON_ONCE(vcq_count < MIN_VCQ_CMDS)) {
		kfree(msg->vcq_data);
		kfree(msg);
		return -EINVAL;
	}
	msg->command_id      = vcq_cmds[1].id;
	msg->vcq_count       = vcq_count;
	msg->num_vcqs        = num_vcqs;
	msg->target_mbx      = target_mbx;
	msg->actual_mbx      = -1;
	msg->complete        = callback;
	msg->completion_data = callback_data;
	msg->backlog_ok      = backlog_ok;
	msg->timeout_jiffies = timeout_jiffies;
	refcount_set(&msg->refs, 1);  /* sole owner: TM subsystem */

	ret = cmh_tm_post_command(msg);
	if (ret && ret != -EBUSY) {
		kfree(msg->vcq_data);
		kfree(msg);
	}
	return ret;
}

/**
 * cmh_tm_submit_sync_noabort() - Sync submit without MBX abort on timeout
 * @vcq_cmds: Array of pre-built VCQ command entries
 * @vcq_count: Total number of entries in @vcq_cmds
 * @num_vcqs: Number of VCQs packed in @vcq_cmds
 * @timeout_hz: Completion timeout in jiffies
 * @orphan_cb: Optional cleanup callback for abandoned DMA buffers
 * @orphan_data: Opaque data passed to @orphan_cb
 *
 * On timeout, if the command was still queued it is cancelled and
 * -EAGAIN is returned (caller may free all resources).  If the VCQ is
 * already in-flight, the waiter drops its refs and returns -EINPROGRESS
 * -- the RH callback will fire when the eSW finishes the VCQ and free
 * the sync_ctx / msg via the refcount mechanism.
 *
 * @orphan_cb is invoked when the last ref on the sync_ctx drops after
 * the waiter abandoned an in-flight VCQ, allowing the caller to defer
 * DMA-buffer cleanup until the eSW finishes writing.
 *
 * This prevents a short-timeout command (e.g. DRBG GENERATE from the
 * hwrng kthread) from aborting the entire MBX and killing unrelated
 * long-running operations (e.g. SLH-DSA sign at 120 s).
 *
 * Return: 0 on success, -EAGAIN if cancelled from queue,
 *         -EINPROGRESS if left in-flight, or negative errno.
 */
int cmh_tm_submit_sync_noabort(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			       u32 num_vcqs, unsigned long timeout_hz,
			       void (*orphan_cb)(void *), void *orphan_data)
{
	struct cmh_sync_ctx *sync;
	struct command_msg *msg;
	unsigned long left;
	int ret;

	WARN_ON_ONCE(!in_task());

	sync = kzalloc_obj(*sync, GFP_KERNEL);
	if (!sync)
		return -ENOMEM;

	msg = kzalloc_obj(*msg, GFP_KERNEL);
	if (!msg) {
		kfree(sync);
		return -ENOMEM;
	}

	init_completion(&sync->done);
	sync->error = 0;
	refcount_set(&sync->refs, 2);

	INIT_LIST_HEAD(&msg->list);
	if (WARN_ON_ONCE(vcq_count < MIN_VCQ_CMDS)) {
		kfree(msg);
		kfree(sync);
		return -EINVAL;
	}
	msg->command_id = vcq_cmds[1].id;
	msg->vcq_data = kmemdup(vcq_cmds, vcq_count * sizeof(*vcq_cmds),
				GFP_KERNEL);
	if (!msg->vcq_data) {
		kfree(msg);
		kfree(sync);
		return -ENOMEM;
	}
	msg->vcq_count  = vcq_count;
	msg->num_vcqs   = num_vcqs;
	msg->target_mbx = -1;
	msg->actual_mbx = -1;
	msg->complete   = cmh_sync_complete;
	msg->completion_data = sync;
	refcount_set(&msg->refs, 2);

	ret = cmh_tm_post_command(msg);
	if (ret) {
		kfree(msg->vcq_data);
		kfree(msg);
		kfree(sync);
		return ret;
	}

	left = wait_for_completion_timeout(&sync->done, timeout_hz);
	if (!left) {
		if (cmh_tm_try_cancel_command(msg)) {
			/* Still queued -- TM never saw it, clean up fully */
			cmh_sync_ctx_put(sync);  /* drop cb ref */
			cmh_sync_ctx_put(sync);  /* drop waiter ref */
			command_msg_put(msg);    /* matches refcount_set(2) */
			command_msg_put(msg);
			return -EAGAIN;
		}

		/*
		 * In-flight: skip ABORT.  Transfer orphan cleanup
		 * ownership to sync_ctx -- the RH callback will
		 * eventually complete this VCQ, and when the last
		 * ref drops, orphan_cb frees any DMA buffers the
		 * eSW was still writing to.
		 */
		dev_dbg_ratelimited(cmh_dev(),
				    "tm: noabort timeout (%lums) cmd=0x%08x, leaving in-flight\n",
				    timeout_hz * 1000 / HZ,
				    msg->command_id);
		sync->orphan_cb   = orphan_cb;
		sync->orphan_data = orphan_data;
		cmh_sync_ctx_put(sync);
		command_msg_put(msg);
		return -EINPROGRESS;
	}

	ret = sync->error;
	cmh_sync_ctx_put(sync);
	command_msg_put(msg);
	return ret;
}

/**
 * cmh_tm_submit_sync() - Synchronous VCQ submit with default timeout
 * @vcq_cmds: Array of pre-built VCQ command entries
 * @vcq_count: Total number of entries in @vcq_cmds
 * @num_vcqs: Number of VCQs packed in @vcq_cmds
 *
 * Convenience wrapper: submits via round-robin MBX selection with the
 * default vcq_timeout_ms.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_tm_submit_sync(struct vcq_cmd *vcq_cmds, u32 vcq_count,
		       u32 num_vcqs)
{
	return cmh_tm_submit_sync_mbx(vcq_cmds, vcq_count, num_vcqs, -1);
}

#define MBX_FLUSH_TIMEOUT_MS	1000
#define MBX_FLUSH_POLL_MIN_US	10
#define MBX_FLUSH_POLL_MAX_US	50

/**
 * cmh_tm_flush_mbx() - Issue MBX_COMMAND_FLUSH and wait for completion
 * @mbx_idx: Mailbox index to flush
 *
 * Resets the eSW child mailbox state: clears the VCQ command queue,
 * resets head/tail, and -- critically -- resets the child temp stack
 * via mbx_hdr_init() (sets hdr->temp back to &cmds[MAX_VCQ_CMDS]).
 *
 * Why this is needed:
 *   KIC derivation commands that output to SYS_REF_TEMP allocate on the
 *   per-MBX child temp LIFO stack (mbx_alloc_temp, each costing
 *   ROUND_UP(len,4)+56 bytes).  These allocations persist across VCQ
 *   completions because mbx_vcq_done() does NOT reset the temp stack.
 *   Without an explicit flush, sequential KIC-TEMP ioctls exhaust the
 *   ~960-byte temp area and subsequent derives fail with ENOMEM.
 *
 * What is NOT affected:
 *   KIC HW keys, datastore objects, DRBG state -- these survive the
 *   flush.  Only the queue pointers and temp stack are reset.
 *
 * Concurrency:
 *   Acquires the per-MBX dispatch_lock mutex to serialise with VCQ
 *   dispatch in submit_vcq().  This prevents the flush from resetting
 *   head/tail while the TM kthread is writing a VCQ to a DMA slot on
 *   the same MBX.  The eSW clears R_MBX_COMMAND to zero once the flush
 *   completes.
 *
 * Return: 0 on success, -EINVAL, -ENODEV, -EBUSY, or -ETIMEDOUT.
 */
int cmh_tm_flush_mbx(s32 mbx_idx)
{
	struct cmh_mbx_config *mbx;
	struct cmh_mbx_txq *txq;
	void __iomem *base;
	u32 reg;
	int ret;

	if (!tm.cfg || mbx_idx < 0 || (u32)mbx_idx >= tm.cfg->mbx_count)
		return -EINVAL;

	mbx = &tm.cfg->mailboxes[mbx_idx];
	base = mbx->reg_base;
	if (!base)
		return -ENODEV;

	txq = &tm.txqs[mbx_idx];
	mutex_lock(&txq->dispatch_lock);

	/* Ensure no command is already pending */
	if (cmh_reg_read32(base, R_MBX_COMMAND) != 0) {
		mutex_unlock(&txq->dispatch_lock);
		return -EBUSY;
	}

	cmh_reg_write32(MBX_COMMAND_FLUSH, base, R_MBX_COMMAND);

	/* Poll until eSW clears the command register */
	ret = read_poll_timeout(cmh_reg_read32, reg, reg == 0,
				MBX_FLUSH_POLL_MIN_US,
				MBX_FLUSH_TIMEOUT_MS * 1000,
				true, base, R_MBX_COMMAND);
	if (ret)
		dev_err(cmh_dev(), "mbx %u flush timeout (cmd=0x%08x)\n",
			mbx->instance,
			cmh_reg_read32(base, R_MBX_COMMAND));

	mutex_unlock(&txq->dispatch_lock);
	return ret;
}

/**
 * cmh_vcq_pack_and_submit() - Pack payload into VCQs and submit sync
 * @payload: Array of VCQ command entries (without headers)
 * @count: Number of entries in @payload
 * @packed: Caller-provided output buffer for packed VCQ data
 * @max_packed: Size of @packed buffer in vcq_cmd entries
 * @target_mbx: Pinned mailbox index, or -1 for round-robin
 *
 * Splits @payload into VCQ-sized chunks, prepends headers, and submits
 * synchronously.
 *
 * Return: 0 on success, -EMSGSIZE if @packed is too small, or
 *         negative errno from submit.
 */
int cmh_vcq_pack_and_submit(const struct vcq_cmd *payload, u32 count,
			    struct vcq_cmd *packed, u32 max_packed,
			    s32 target_mbx)
{
	u32 max_per_vcq = cmh_tm_max_cmds_per_vcq();
	u32 max_payload_per = max_per_vcq - 1;
	u32 num_vcqs = 0, total = 0, i = 0;

	while (i < count) {
		u32 chunk = min_t(u32, count - i, max_payload_per);
		u32 vcq_cmds = chunk + 1;

		if (total + vcq_cmds > max_packed)
			return -EMSGSIZE;

		vcq_set_header(&packed[total], vcq_cmds);
		memcpy(&packed[total + 1], &payload[i],
		       chunk * sizeof(struct vcq_cmd));

		total += vcq_cmds;
		i += chunk;
		num_vcqs++;
	}

	return cmh_tm_submit_sync_mbx(packed, total, num_vcqs, target_mbx);
}

/**
 * cmh_vcq_pack_and_submit_async() - Pack payload and submit async
 * @payload: Array of VCQ command entries (without headers)
 * @count: Number of entries in @payload
 * @packed: Caller-provided output buffer for packed VCQ data
 * @max_packed: Size of @packed buffer in vcq_cmd entries
 * @target_mbx: Pinned mailbox index, or -1 for round-robin
 * @callback: Completion callback
 * @callback_data: Opaque data passed to @callback
 * @backlog_ok: Allow backlogging if CMQ is full
 * @timeout_jiffies: Per-request timeout (0 = no timeout)
 *
 * Asynchronous variant of cmh_vcq_pack_and_submit().  Splits @payload
 * into VCQ-sized chunks, prepends headers, and submits via
 * cmh_tm_submit_async().
 *
 * Return: 0 on success, -EBUSY if backlogged, -EMSGSIZE if @packed
 *         is too small, or negative errno from submit.
 */
int cmh_vcq_pack_and_submit_async(const struct vcq_cmd *payload, u32 count,
				  struct vcq_cmd *packed, u32 max_packed,
				  s32 target_mbx,
				  cmh_completion_fn callback,
				  void *callback_data,
				  bool backlog_ok,
				  unsigned long timeout_jiffies)
{
	u32 max_per_vcq = cmh_tm_max_cmds_per_vcq();
	u32 max_payload_per = max_per_vcq - 1;
	u32 num_vcqs = 0, total = 0, i = 0;

	while (i < count) {
		u32 chunk = min_t(u32, count - i, max_payload_per);
		u32 vcq_cmds = chunk + 1;

		if (total + vcq_cmds > max_packed)
			return -EMSGSIZE;

		vcq_set_header(&packed[total], vcq_cmds);
		memcpy(&packed[total + 1], &payload[i],
		       chunk * sizeof(struct vcq_cmd));

		total += vcq_cmds;
		i += chunk;
		num_vcqs++;
	}

	return cmh_tm_submit_async(packed, total, num_vcqs, target_mbx,
				   callback, callback_data, backlog_ok,
				   timeout_jiffies);
}

/**
 * cmh_tm_peek_transaction() - Peek at the head of a mailbox TXQ
 * @mbx_idx: Mailbox index to inspect
 *
 * Returns a pointer to the oldest in-flight transaction without
 * removing it from the queue.  The caller must not free the returned
 * object.
 *
 * Return: Pointer to the head transaction, or NULL if empty.
 */
struct transaction_obj *cmh_tm_peek_transaction(u32 mbx_idx)
{
	struct cmh_mbx_txq *txq;
	struct transaction_obj *txn = NULL;
	unsigned long flags;

	if (!tm.txqs || mbx_idx >= tm.cfg->mbx_count)
		return NULL;

	txq = &tm.txqs[mbx_idx];

	spin_lock_irqsave(&txq->lock, flags);
	if (!list_empty(&txq->head))
		txn = list_first_entry(&txq->head, struct transaction_obj,
				       list);
	spin_unlock_irqrestore(&txq->lock, flags);

	return txn;
}

/**
 * cmh_tm_pop_transaction() - Remove and return the head of a MBX TXQ
 * @mbx_idx: Mailbox index to pop from
 *
 * Dequeues the oldest in-flight transaction from the per-mailbox
 * transaction queue.  The caller takes ownership and must eventually
 * call cmh_txn_finish() or txn_put().
 *
 * Return: Pointer to the dequeued transaction, or NULL if empty.
 */
struct transaction_obj *cmh_tm_pop_transaction(u32 mbx_idx)
{
	struct cmh_mbx_txq *txq;
	struct transaction_obj *txn;
	unsigned long flags;

	if (!tm.txqs || mbx_idx >= tm.cfg->mbx_count)
		return NULL;

	txq = &tm.txqs[mbx_idx];

	spin_lock_irqsave(&txq->lock, flags);
	if (list_empty(&txq->head)) {
		spin_unlock_irqrestore(&txq->lock, flags);
		return NULL;
	}
	txn = list_first_entry(&txq->head, struct transaction_obj, list);
	list_del_init(&txn->list);
	txq->depth--;
	spin_unlock_irqrestore(&txq->lock, flags);

	return txn;
}

/* -- debugfs timeout accessors ----------------------------------------- */

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
/**
 * cmh_tm_timeout_async_ptr() - Return pointer to async_timeout_ms for debugfs
 *
 * Return: pointer to the static async_timeout_ms variable.
 */
unsigned int *cmh_tm_timeout_async_ptr(void)    { return &async_timeout_ms; }

/**
 * cmh_tm_timeout_vcq_ptr() - Return pointer to vcq_timeout_ms for debugfs
 *
 * Return: pointer to the static vcq_timeout_ms variable.
 */
unsigned int *cmh_tm_timeout_vcq_ptr(void)      { return &vcq_timeout_ms; }

/**
 * cmh_tm_timeout_slow_op_ptr() - Return pointer to slow_op_timeout_ms for debugfs
 *
 * Return: pointer to the static slow_op_timeout_ms variable.
 */
unsigned int *cmh_tm_timeout_slow_op_ptr(void)  { return &slow_op_timeout_ms; }

/**
 * cmh_tm_timeout_drain_ptr() - Return pointer to drain_timeout_ms for debugfs
 *
 * Return: pointer to the static drain_timeout_ms variable.
 */
unsigned int *cmh_tm_timeout_drain_ptr(void)    { return &drain_timeout_ms; }
#endif
