/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Transaction Manager
 *
 * Dedicated kthread managing concurrent VCQ submissions.
 *
 * Callers post command_msg objects into the Command Message Queue (CMQ).
 * The TM thread dequeues them, selects a mailbox, builds VCQ(s) in the
 * DMA queue slot, creates a transaction_obj, and rings the doorbell.
 *
 * The Response Handler (cmh_rh.c) walks per-mailbox transaction queues
 * when an IRQ fires and fires completion callbacks.
 */

#ifndef CMH_TXN_H
#define CMH_TXN_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/refcount.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <crypto/algapi.h>

#include "cmh_config.h"
#include "cmh_vcq.h"

/* Command Message (caller -> TM) */

typedef void (*cmh_completion_fn)(void *data, int error);

struct command_msg {
	struct list_head    list;           /* CMQ linked list node */
	u32                 command_id;     /* VCQ_CMD_ID(core, flags, span, cmd) */
	void               *vcq_data;      /* heap-owned copy of VCQ entries */
	u32                 vcq_count;      /* total vcq_cmd entries across all VCQs */
	u32                 num_vcqs;       /* how many VCQs in vcq_data (0 or 1 = single) */
	s32                 target_mbx;     /* MBX index from core affinity, or -1 fallback */
	s32                 actual_mbx;     /* MBX selected by TM thread, -1 until dispatched */
	cmh_completion_fn   complete;       /* completion callback (may be NULL) */
	void               *completion_data;
	refcount_t          refs;           /* submit_sync: 2 = waiter + TM */
	bool                backlog_ok;     /* accept into backlog when CMQ is full */
	unsigned long       timeout_jiffies;/* per-txn async timeout (0 = none) */
};

/* Transaction Object (TM -> RH) */

/* Per-transaction FSM states for async timeout resolution */
#define TXN_INFLIGHT	0
#define TXN_COMPLETE	1
#define TXN_TIMED_OUT	2

struct transaction_obj {
	struct list_head    list;           /* per-mailbox txn queue node */
	u32                 first_vcq_id;
	u32                 last_vcq_id;
	u32                 mailbox_idx;    /* index into cfg->mailboxes[] */
	u32                 command_id;     /* VCQ_CMD_ID from first payload cmd */
	int                 error_code;
	cmh_completion_fn   complete;
	void               *completion_data;
	atomic_t            state;          /* TXN_INFLIGHT / COMPLETE / TIMED_OUT */
	struct timer_list   timeout_timer;  /* per-request async timeout */
	refcount_t          refs;           /* owner + timer (if armed) */
};

/* Per-Mailbox Transaction Queue */

struct cmh_mbx_txq {
	struct list_head    head;
	spinlock_t          lock;           /* protects head list + depth */
	u32                 depth;          /* number of in-flight transactions */
	struct mutex        dispatch_lock;  /* serialises VCQ dispatch + MBX flush */
};

/* Public Interface */

/**
 * cmh_tm_init() - Initialise the Transaction Manager
 * @cfg: Global device configuration (mailbox layout, IRQ, etc.)
 *
 * Starts the TM kthread and initialises per-mailbox transaction queues.
 *
 * Return: 0 on success, negative errno on failure.
 */
int  cmh_tm_init(struct cmh_config *cfg);

/**
 * cmh_tm_cleanup() - Stop the TM kthread and drain all queues
 */
void cmh_tm_cleanup(void);

/**
 * cmh_tm_quiesce() - Stop TM kthread and drain in-flight transactions
 *
 * Stops the TM kthread, rejects new posts, then waits (with a
 * configurable timeout) for all per-MBX transaction queues to drain.
 * If the timeout fires, remaining transactions are cancelled with
 * -ECANCELED.
 */
void cmh_tm_quiesce(void);

/**
 * cmh_tm_resume() - Restart the TM kthread after resume
 *
 * Return: 0 on success, negative errno if the kthread fails to start.
 */
int  cmh_tm_resume(void);

/**
 * cmh_tm_post_command() - Post a command to the TM for submission
 * @msg: Command message with pre-built VCQ data and completion callback
 *
 * Round-robin selects the next MBX with enough free slots for
 * msg->num_vcqs VCQs.  All VCQs in a message are written to
 * consecutive slots on the same MBX (back-to-back).
 * The caller retains ownership of @msg until the completion callback fires.
 *
 * Return: 0 on success, -EAGAIN if queue full, -ENODEV if TM stopped.
 */
int  cmh_tm_post_command(struct command_msg *msg);

/*
 * Synchronous submit -- post one or more VCQs and wait for completion.
 *
 * Combines post_command + refcounted wait + timeout + cancel into one
 * call.  This is the standard pattern for all synchronous crypto ops.
 *
 * Context: must be called from a sleepable (task) context.
 *          Performs GFP_KERNEL allocations and sleeps on
 *          wait_for_completion_timeout().  A WARN_ON_ONCE fires
 *          if called from atomic / IRQ / softirq context.
 *
 * vcq_cmds:   pre-built VCQ array (headers + commands, contiguous)
 * vcq_count:  total number of vcq_cmd entries across all VCQs
 * num_vcqs:   number of VCQs in the array (0 or 1 = single VCQ)
 *
 * For multi-VCQ submissions, the array contains multiple VCQs laid
 * out contiguously, each starting with its own header.  All VCQs are
 * written to consecutive MBX slots and share one transaction object.
 *
 * Returns 0 on success, -ETIMEDOUT, or CMH eSW error code.
 */
int  cmh_tm_submit_sync(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			u32 num_vcqs);

/*
 * Synchronous submit pinned to a specific mailbox.
 * target_mbx: -1 = round-robin, >= 0 = pin to that MBX index.
 */
int  cmh_tm_submit_sync_mbx(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			    u32 num_vcqs, s32 target_mbx);

/*
 * Synchronous submit with explicit timeout.
 * timeout_hz: completion timeout in jiffies (use msecs_to_jiffies()).
 */

/*
 * Extended timeout for slow crypto operations: RSA keygen, PQC
 * keygen/sign/verify.  Controlled by the slow_op_timeout_ms module
 * parameter.
 */
unsigned long cmh_tm_slow_op_timeout_jiffies(void);

int  cmh_tm_submit_sync_tmo(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			    u32 num_vcqs, s32 target_mbx,
			    unsigned long timeout_hz);

/*
 * Synchronous submit that never issues MBX_COMMAND_ABORT on timeout.
 * Returns -EAGAIN if cancelled from queue, -EINPROGRESS if the VCQ is
 * left in-flight.  On -EINPROGRESS, @orphan_cb(@orphan_data) will be
 * called when the VCQ eventually completes (RH callback fires and the
 * last sync_ctx ref drops).  Use this to defer DMA cleanup.
 * Safe for background/kthread callers that must not disrupt other MBX work.
 */
int  cmh_tm_submit_sync_noabort(struct vcq_cmd *vcq_cmds, u32 vcq_count,
				u32 num_vcqs, unsigned long timeout_hz,
				void (*orphan_cb)(void *),
				void *orphan_data);

/*
 * Asynchronous submit -- post VCQs and return immediately.
 *
 * On successful return (0), the provided @callback may be invoked from
 * either the RH threaded IRQ context (normal completion path) or the TM
 * kthread (if VCQ dispatch to the HW ring fails after the message was
 * posted to the CMQ).  The caller must not assume a specific callback
 * context.
 *
 * After a successful post, the caller must NOT touch VCQ buffers --
 * ownership transfers to the TM.  If this function returns non-zero,
 * the message was not posted, the callback will NOT fire, and the caller
 * must perform cleanup.
 *
 * Uses GFP_ATOMIC internally -- the crypto API may invoke driver ops
 * from softirq context (e.g. IPsec), so GFP_KERNEL would deadlock.
 *
 * If @backlog_ok is true and the CMQ is full, the message is placed on
 * an overflow backlog queue and -EBUSY is returned.  The caller must
 * treat -EBUSY as "accepted" (like -EINPROGRESS): the callback WILL
 * fire once the request is promoted from backlog and completes.  When
 * @backlog_ok is false, CMQ-full returns -EAGAIN (caller must clean up).
 *
 * Returns: 0 on successful post, -EBUSY (backlogged -- callback will
 *          fire), -ENOMEM, -EINVAL (bad vcq_count), -EAGAIN (CMQ full,
 *          no backlog), -ENODEV.
 */
int  cmh_tm_submit_async(struct vcq_cmd *vcq_cmds, u32 vcq_count,
			 u32 num_vcqs, s32 target_mbx,
			 cmh_completion_fn callback, void *callback_data,
			 bool backlog_ok, unsigned long timeout_jiffies);

/**
 * cmh_tm_async_timeout_jiffies() - Default per-request async timeout
 *
 * Returns the debugfs-configurable timeout for symmetric data-path
 * ops (async_timeout_ms converted to jiffies).  Akcipher/kpp callers
 * should pass 0 instead (no per-request timeout; vcq_timeout_ms is the
 * safety net).
 */
unsigned long cmh_tm_async_timeout_jiffies(void);

/**
 * cmh_tm_flush_mbx() - Issue MBX_COMMAND_FLUSH and wait for completion
 * @mbx_idx: Mailbox index
 *
 * Resets the eSW child mailbox state including the temp stack.
 * Must be called when no VCQ submission is in progress on @mbx_idx.
 *
 * Return: 0 on success, -ETIMEDOUT if eSW does not clear the command,
 *         -EBUSY if a command is already pending.
 */
int  cmh_tm_flush_mbx(s32 mbx_idx);

/**
 * cmh_tm_try_cancel_command() - Try to cancel a queued command
 * @msg: Command message to cancel
 *
 * Return: true if removed from CMQ, false if already consumed by the TM thread.
 */
bool cmh_tm_try_cancel_command(struct command_msg *msg);

/**
 * cmh_tm_peek_transaction() - Peek at the oldest transaction on a mailbox
 * @mbx_idx: Mailbox index
 *
 * For use by the Response Handler.  Caller must hold txq->lock or call
 * from a context where no concurrent pop is possible (e.g. threaded IRQ).
 *
 * Return: Pointer to the oldest transaction_obj, or NULL if empty.
 */
struct transaction_obj *cmh_tm_peek_transaction(u32 mbx_idx);

/**
 * cmh_tm_pop_transaction() - Remove and return the oldest transaction
 * @mbx_idx: Mailbox index
 *
 * Return: Pointer to the removed transaction_obj, or NULL if empty.
 */
struct transaction_obj *cmh_tm_pop_transaction(u32 mbx_idx);

/**
 * cmh_txn_finish() - Complete a transaction with FSM + timer handling
 * @txn: Transaction popped from the TXQ
 * @error: Error code (0 for success, negative errno)
 *
 * Resolves the timer-vs-completion race via atomic cmpxchg, cancels
 * the per-txn timeout timer if still pending, fires the completion
 * callback (if this path wins the race), and drops the owner reference.
 * The transaction is freed when the last reference is dropped.
 *
 * Called by the Response Handler after popping a completed transaction.
 */
void cmh_txn_finish(struct transaction_obj *txn, int error);

/**
 * cmh_tm_max_cmds_per_vcq() - Max vcq_cmd entries per MBX slot
 *
 * Returns the minimum across all configured MBXes so callers can pack
 * VCQs without knowing which MBX will be selected.
 *
 * Return: At least MIN_VCQ_CMDS (2).
 */
u32  cmh_tm_max_cmds_per_vcq(void);

/**
 * cmh_tm_mbx_count() - Return the number of configured mailboxes
 *
 * Return: cfg->mbx_count.
 */
u32  cmh_tm_mbx_count(void);

/**
 * cmh_core_default_id() - Return the default core_id for a core type
 * @type: Logical core type enum
 *
 * Returns the core_id of the first (index-0) instance without advancing
 * the round-robin counter.  Intended for callers pinned to a fixed MBX
 * (e.g. mgmt ioctls on MGMT_MBX) that only need the VCQ core_id field.
 *
 * In multi-instance configurations the returned core_id is always that
 * of instance[0], regardless of which MBX instance[0] is assigned to.
 * Mgmt callers submit on MGMT_MBX (0) -- the eSW accepts any valid
 * core_id on any MBX for command dispatch.
 *
 * Return: u32 core_id.
 */
u32  cmh_core_default_id(enum cmh_core_type type);

/**
 * cmh_core_select_instance() - Multi-instance core dispatch selection
 * @type: Logical core type enum
 *
 * Returns the next (core_id, mbx_idx) pair for @type using round-robin
 * across configured instances.  On first use for an instance whose MBX
 * is not pre-assigned, atomically assigns the next available MBX.
 *
 * With single-instance defaults, this degenerates to the same behaviour
 * as the old single-entry core_to_mbx[] table -- one core type, one MBX.
 *
 * Return: struct core_dispatch with core_id and mbx_idx.
 */
struct core_dispatch cmh_core_select_instance(enum cmh_core_type type);

/**
 * cmh_core_num_instances() - Return count of configured instances
 * @type: Logical core type enum
 *
 * Return: Number of instances (>= 1) for @type.
 */
u32  cmh_core_num_instances(enum cmh_core_type type);

/**
 * cmh_core_get_instance() - Get a specific instance by index
 * @type: Logical core type enum
 * @idx: Instance index (0-based, must be < cmh_core_num_instances())
 *
 * Returns (core_id, mbx_idx) for the given instance without advancing
 * the round-robin counter.  Triggers auto-assign if the instance has
 * no MBX yet.
 *
 * Return: struct core_dispatch with core_id and mbx_idx.
 */
struct core_dispatch cmh_core_get_instance(enum cmh_core_type type, u32 idx);

/**
 * cmh_tm_affinity_reset() - Reset all core-to-MBX assignments
 *
 * Called during init and cleanup.
 */
void cmh_tm_affinity_reset(void);

/**
 * cmh_tm_txq_completion_notify() - Wake TM thread after TXQ completion
 *
 * Called by the Response Handler after completing a transaction to
 * unblock the TM thread if it is waiting for a free MBX slot.
 */
void cmh_tm_txq_completion_notify(void);

/*
 * Pack @count payload commands (no headers) into one or more VCQs
 * respecting the per-slot size limit, then submit synchronously.
 *
 * @payload:    flat array of vcq_cmd entries (no headers)
 * @count:      number of entries in @payload
 * @packed:     caller-provided scratch buffer for the packed output
 * @max_packed: size of @packed in vcq_cmd entries
 * @target_mbx: -1 = round-robin, >= 0 = pin to this MBX index
 *
 * Each VCQ gets its own header.  All VCQs are submitted as a single
 * back-to-back transaction on the same MBX.
 */
int  cmh_vcq_pack_and_submit(const struct vcq_cmd *payload, u32 count,
			     struct vcq_cmd *packed, u32 max_packed,
			     s32 target_mbx);

/**
 * cmh_vcq_pack_and_submit_async() - Pack payload commands and submit async
 * @payload: Flat array of VCQ command entries (no headers)
 * @count: Number of entries in @payload
 * @packed: Caller-provided scratch buffer for packed output
 * @max_packed: Size of @packed in vcq_cmd entries
 * @target_mbx: Mailbox index (-1 for round-robin)
 * @callback: Completion callback
 * @callback_data: Opaque data passed to @callback
 * @backlog_ok: If true, accept into backlog when CMQ is full
 * @timeout_jiffies: Per-request timeout (0 to disable)
 *
 * Async variant of cmh_vcq_pack_and_submit().  Returns 0 on successful
 * post; after a successful post, @callback may run from RH threaded IRQ
 * context on normal completion, from the TM kthread if VCQ dispatch
 * fails after posting, or from TM teardown paths such as
 * cmh_tm_cleanup() / cmh_tm_quiesce() when queued or in-flight work is
 * cancelled.  Callers must not assume a single callback context.  On
 * non-zero return, the callback will NOT fire.
 *
 * @payload:          flat array of vcq_cmd entries (no headers)
 * @count:            number of entries in @payload
 * @packed:           caller-provided scratch buffer for the packed output
 * @max_packed:       size of @packed in vcq_cmd entries
 * @target_mbx:       -1 = round-robin, >= 0 = pin to this MBX index
 * @callback:         completion callback (may run from IRQ or TM context)
 * @callback_data:    opaque pointer passed to @callback
 * @backlog_ok:       if true, queue the request when all MBXs are busy
 * @timeout_jiffies:  maximum wait time for MBX slot (0 = no wait)
 *
 * Return: 0 on successful post, -EBUSY (backlogged), negative errno on failure.
 */
int  cmh_vcq_pack_and_submit_async(const struct vcq_cmd *payload, u32 count,
				   struct vcq_cmd *packed, u32 max_packed,
				   s32 target_mbx,
				   cmh_completion_fn callback,
				   void *callback_data,
				   bool backlog_ok,
				   unsigned long timeout_jiffies);

/* debugfs timeout accessors (debug builds only) */
#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
unsigned int *cmh_tm_timeout_async_ptr(void);
unsigned int *cmh_tm_timeout_vcq_ptr(void);
unsigned int *cmh_tm_timeout_slow_op_ptr(void);
unsigned int *cmh_tm_timeout_drain_ptr(void);
#endif

/* -- Crypto request completion helper ---------------------------------- */

struct device *cmh_dev(void);

/**
 * cmh_complete() - Complete a crypto request with optional error logging
 * @req: The async crypto request to complete
 * @err: Error code (0 = success, -EINPROGRESS = backlog promotion signal)
 *
 * Logs a rate-limited diagnostic on genuine errors, then hands the
 * request back to the crypto framework.  -EINPROGRESS is excluded from
 * logging -- it is the crypto API's backlog promotion notification, not
 * an error.  Centralizes error reporting so individual algorithm drivers
 * do not need per-callback logging.
 */
static inline void cmh_complete(struct crypto_async_request *req, int err)
{
	if (err && err != -EINPROGRESS) {
		/*
		 * For template instances (e.g. hmac(sha3-512-cmh)) the
		 * driver name will be the outer template's, not ours.
		 * Still useful for triage -- identifies the failing tfm.
		 */
		dev_dbg_ratelimited(cmh_dev(), "op error: alg=%s err=%d\n",
				    crypto_tfm_alg_driver_name(req->tfm),
				    err);
	}
	crypto_request_complete(req, err);
}

#endif /* CMH_TXN_H */
