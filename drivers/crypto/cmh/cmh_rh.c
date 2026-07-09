// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Response Handler
 *
 * IRQ-driven completion processing using request_threaded_irq():
 *
 *   Hardirq:  For each MBX, read R_MBX_INTERRUPT.  If any bit is set,
 *             W1C-clear it and mark the MBX for threaded processing.
 *             Return IRQ_WAKE_THREAD if any MBX had work.
 *
 *   Thread:   For each pending MBX, read R_MBX_QUEUE_HEAD.  Walk the
 *             per-MBX transaction queue (oldest first): for every txn
 *             whose last_vcq_id < new_head, check status, fire the
 *             completion callback, and free the transaction object.
 *
 * The DT "cri,cmh" node declares one PLIC interrupt per mailbox,
 * matching the real CMH ch_sys_interrupt_mbx[N-1:0] topology.
 * Each MBX gets its own Linux virq; the same hardirq/thread pair
 * is registered for all of them.  The handler still scans all
 * mailboxes on every invocation -- this is intentional, as it
 * provides robustness against coalesced or missed edges.
 *
 * IRQ source: resolved from the "cri,cmh" DT node at init time.
 * The module's irq= parameter can override with a single shared IRQ.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#include "cmh_rh.h"
#include "cmh_txn.h"
#include "cmh_registers.h"
#include "cmh_config.h"
#include "cmh_debugfs.h"
#include "cmh_dma.h"

/* Per-mailbox IRQ bookkeeping */
struct cmh_rh_mbx {
	u32        last_head;   /* last-observed MBX head position */
	atomic_t   irq_bits;   /* interrupt bits saved by hardirq (atomic_or) */
	bool       pending;     /* threaded handler should process this MBX */
	bool       restart_pending; /* RESTART issued, awaiting eSW ack */
	u32        restart_retries; /* watchdog ticks since RESTART issued */
	u32        flush_count;     /* consecutive failed FLUSH escalations */
	bool       wedged;          /* recovery failed, MBX offline */
	u32        abort_stall_ticks; /* ticks since async timeout ABORT issued */
};

/* Module-level RH state */
static struct {
	struct cmh_config      *cfg;
	int                     irqs[CMH_MAX_CONFIGURED_MBX]; /* per-MBX virqs */
	u32                     nirqs;          /* number of registered IRQs */
	struct cmh_rh_mbx      *mbx;            /* array[cfg->mbx_count] */
	atomic_t                irq_count;      /* hardirq invocation counter */
	bool                    active;
} rh;

/*
 * Serialise the read-last_head / process_mbx / update-last_head
 * sequence between the threaded IRQ handler (process context) and
 * the watchdog timer (softirq context).  Without this, a timer
 * softirq can preempt the kthread mid-sequence, causing both paths
 * to process the same head advance and prematurely complete a
 * subsequent transaction before the CMH eSW has written its DMA
 * output -- leading to data corruption and SLAB freelist poisoning.
 *
 * The kthread acquires with spin_lock_bh (disables softirqs), the
 * watchdog acquires with spin_lock (already in softirq context).
 */
static DEFINE_SPINLOCK(rh_process_lock);

/*
 * Watchdog timer -- missed-IRQ recovery.
 *
 * Fires every watchdog_ms while rh.active.  Reads MBX head registers;
 * if any head has advanced without an IRQ, processes completions and
 * logs a notice.  Standard kernel pattern, analogous to NIC watchdog
 * timers.
 *
 * Safe from timer/softirq context: cmh_reg_read32() is an MMIO read,
 * cmh_tm_pop_transaction() uses spin_lock_irqsave(), and TM completion
 * callbacks (crypto_request_complete et al.) are documented safe from
 * any context including softirq.  rh_process_lock serialises the
 * head-read / process / head-update sequence against the threaded
 * IRQ handler to prevent double-processing of the same completion.
 *
 * Default 200 ms (5 fires/s) provides ~10 recovery attempts within
 * the default vcq_timeout_ms (2 s).  Tune via debugfs config/watchdog_ms
 * for platforms where interrupt delivery is more reliable (e.g. MSI on
 * FPGA/silicon -- 500 ms--1 s may suffice as a safety net).
 */
#define CMH_RH_WATCHDOG_MS_DEFAULT  200

/*
 * Floor for watchdog_ms to prevent a zero/near-zero value from
 * spinning the timer in a tight softirq loop.  Enforced at the
 * point of use so debugfs writes are never rejected.
 */
#define CMH_RH_WATCHDOG_MS_MIN      10

/*
 * Maximum watchdog ticks to wait for the eSW to process RESTART
 * before escalating to FLUSH.  At the default 200 ms interval,
 * 5 retries = 1 s -- generous for an operation that should take
 * microseconds.  If the eSW hasn't responded by then, issue
 * MBX_COMMAND_FLUSH to hard-reset the mailbox state.
 */
#define CMH_RH_RESTART_MAX_RETRIES  5

/*
 * Maximum consecutive FLUSH escalations before marking the MBX as
 * wedged.  Each FLUSH cycle takes RESTART_MAX_RETRIES watchdog ticks
 * (~1 s at default interval).  Two failed FLUSHes (~2 s total)
 * strongly indicate the eSW is not processing MBX commands at all.
 */
#define CMH_RH_FLUSH_MAX_FAILURES   2

/*
 * Time budget (ms) after an async timeout ABORT before escalating
 * to FLUSH + force-drain.  Converted to watchdog ticks at runtime
 * via abort_stall_ms / watchdog_ms, so the actual wall-clock bound
 * stays constant regardless of watchdog_ms tuning.
 *
 * The stall detector fires when:
 *   - The head-of-queue transaction is in TXN_TIMED_OUT state
 *   - HEAD hasn't advanced (eSW didn't process the ABORT)
 *   - abort_stall_ticks exceeds the derived threshold
 *
 * At that point we issue FLUSH + force-drain, completing all pending
 * transactions with -ETIMEDOUT and waking any blocked waiters.
 *
 * Default 5000 ms bounds worst-case D-state to
 * async_timeout (2 s) + abort_stall (5 s) = ~7 s.
 */
#define CMH_RH_ABORT_STALL_MS       5000

static unsigned int watchdog_ms = CMH_RH_WATCHDOG_MS_DEFAULT;

/*
 * Re-poke R_MBX_QUEUE_TAIL to generate a fresh interrupt to the eSW.
 * Writing the current value back is a queue no-op but guarantees a
 * SIC interrupt edge, ensuring the eSW wakes from WFI.
 */
static void cmh_rh_poke_tail(void __iomem *base)
{
	u32 tail = cmh_reg_read32(base, R_MBX_QUEUE_TAIL);

	cmh_reg_write32(tail, base, R_MBX_QUEUE_TAIL);
}

/*
 * Drain all remaining in-flight transactions for a mailbox, completing
 * each with the given error code.  Called after FLUSH (which discards
 * all queued VCQs) or when marking a mailbox as wedged.  Updates
 * last_head to the current hardware HEAD so subsequent polls don't
 * re-process the same (now-dead) VCQ IDs as successful completions.
 *
 * Caller must hold rh_process_lock.
 */
static void cmh_rh_drain_mbx(u32 mbx_idx, int error)
{
	struct transaction_obj *txn;

	while ((txn = cmh_tm_pop_transaction(mbx_idx)) != NULL) {
		dev_dbg(cmh_dev(), "rh: mbx[%u] drain vcq=%u..%u err=%d\n",
			mbx_idx, txn->first_vcq_id,
			txn->last_vcq_id, error);
		cmh_txn_finish(txn, error);
		cmh_tm_txq_completion_notify();
	}

	rh.mbx[mbx_idx].last_head =
		cmh_reg_read32(rh.cfg->mailboxes[mbx_idx].reg_base,
			       R_MBX_QUEUE_HEAD);
}

/**
 * cmh_rh_force_drain_mbx() - FLUSH + drain a mailbox from external context
 * @mbx_idx: Mailbox index to drain
 *
 * Issues MBX_COMMAND_FLUSH to the eSW, drains all pending transactions
 * (completing each with -ECANCELED), and resets all recovery bookkeeping
 * including the wedged flag.  This is an administrative last-resort
 * recovery path exposed via debugfs.
 *
 * Context: process context.  Acquires rh_process_lock internally.
 */
void cmh_rh_force_drain_mbx(u32 mbx_idx)
{
	void __iomem *base;

	if (!rh.cfg || !rh.mbx || mbx_idx >= rh.cfg->mbx_count)
		return;

	base = rh.cfg->mailboxes[mbx_idx].reg_base;

	dev_warn(cmh_dev(), "rh: force-drain mbx[%u] (debugfs)\n", mbx_idx);
	spin_lock_bh(&rh_process_lock);
	cmh_reg_write32(MBX_IRQ_MASK, base, R_MBX_INTERRUPT);
	cmh_reg_write32(MBX_COMMAND_FLUSH, base, R_MBX_COMMAND);
	cmh_rh_poke_tail(base);
	cmh_rh_drain_mbx(mbx_idx, -ECANCELED);
	rh.mbx[mbx_idx].abort_stall_ticks = 0;
	WRITE_ONCE(rh.mbx[mbx_idx].restart_pending, false);
	rh.mbx[mbx_idx].restart_retries = 0;
	rh.mbx[mbx_idx].flush_count = 0;
	WRITE_ONCE(rh.mbx[mbx_idx].wedged, false);
	spin_unlock_bh(&rh_process_lock);
}

/**
 * cmh_rh_mbx_is_wedged() - Check if a mailbox is permanently wedged
 * @mbx_idx: Mailbox index to check
 *
 * Return: true if the mailbox has failed recovery and is offline.
 */
bool cmh_rh_mbx_is_wedged(u32 mbx_idx)
{
	if (!rh.mbx || !rh.cfg || mbx_idx >= rh.cfg->mbx_count)
		return false;

	return READ_ONCE(rh.mbx[mbx_idx].wedged);
}

/**
 * cmh_rh_abort_mbx() - Issue MBX_COMMAND_ABORT under rh_process_lock
 * @mbx_idx: Mailbox index to abort
 *
 * Serialises the ABORT write with RESTART/FLUSH commands issued by the
 * watchdog, preventing command-register clobber races.  Safe to call
 * from any context (uses spin_lock_bh).
 */
void cmh_rh_abort_mbx(u32 mbx_idx)
{
	void __iomem *base;

	if (!rh.cfg || !rh.mbx || mbx_idx >= rh.cfg->mbx_count)
		return;

	base = rh.cfg->mailboxes[mbx_idx].reg_base;

	spin_lock_bh(&rh_process_lock);
	cmh_reg_write32(MBX_COMMAND_ABORT, base, R_MBX_COMMAND);
	spin_unlock_bh(&rh_process_lock);
}

static struct timer_list rh_watchdog;

/*
 * Hardirq handler -- runs with interrupts disabled.
 *
 * Read and W1C-clear R_MBX_INTERRUPT for each mailbox.
 * If any MBX had a pending interrupt, return IRQ_WAKE_THREAD.
 * Shared-IRQ safe: returns IRQ_NONE if we didn't handle anything.
 */
static irqreturn_t cmh_rh_hardirq(int irq, void *data)
{
	struct cmh_config *cfg = data;
	bool handled = false;
	u32 i;

	for (i = 0; i < cfg->mbx_count; i++) {
		void __iomem *base = cfg->mailboxes[i].reg_base;
		u32 bits;

		bits = cmh_reg_read32(base, R_MBX_INTERRUPT);
		if (!bits)
			continue;

		/* W1C: write back the set bits to clear them */
		cmh_reg_write32(bits, base, R_MBX_INTERRUPT);

		/*
		 * Accumulate bits atomically so a second hardirq
		 * firing while the threaded handler runs does not
		 * overwrite the first set of bits.
		 */
		atomic_or((int)bits, &rh.mbx[i].irq_bits);
		WRITE_ONCE(rh.mbx[i].pending, true);
		handled = true;
	}

	/*
	 * Ordering: the kernel IRQ threading infrastructure
	 * performs a full barrier between hardirq return and
	 * the threaded handler invocation.
	 */
	if (handled)
		atomic_inc(&rh.irq_count);

	return handled ? IRQ_WAKE_THREAD : IRQ_NONE;
}

/*
 * Process completions for a single mailbox.
 *
 * Walk the per-MBX transaction queue FIFO.  For each transaction
 * whose last_vcq_id is strictly less than the new head, fire the
 * completion callback and free the object.
 *
 * "Strictly less than" using signed (s32) arithmetic handles wrap-around:
 * the CMH eSW uses monotonically increasing 32-bit VCQ IDs.
 */
static void cmh_rh_process_mbx(u32 mbx_idx, u32 new_head, u32 irq_bits)
{
	struct transaction_obj *txn;
	int error = 0;

	/* Determine error state from saved IRQ bits */
	if (irq_bits & MBX_ERROR_IRQ) {
		void __iomem *base = rh.cfg->mailboxes[mbx_idx].reg_base;
		u32 status = cmh_reg_read32(base, R_MBX_STATUS);

		error = -EIO;
		dev_dbg(cmh_dev(), "rh: mbx[%u] error status=0x%08x (code=%u cmd_idx=%u)\n",
			mbx_idx, status,
		       MBX_STATUS_ERROR_CODE(status),
		       MBX_STATUS_CMD_INDEX(status));

		/*
		 * ECHILD (10) in the parent status means a child VCQ
		 * failed internally.  Read R_MBX_CHILD for the actual
		 * root cause (real errno, child core ID, child cmd idx).
		 */
		if (MBX_STATUS_ERROR_CODE(status) == ECHILD) {
			u32 child = cmh_reg_read32(base, R_MBX_CHILD);

			dev_dbg(cmh_dev(),
				"rh: mbx[%u] child error=0x%08x (core=%u code=%u cmd_idx=%u)\n",
				mbx_idx, child,
				MBX_STATUS_CORE_ID(child),
				MBX_STATUS_ERROR_CODE(child),
				MBX_STATUS_CMD_INDEX(child));
		}

		/*
		 * CMH eSW does not advance head on error -- the MBX is
		 * stuck in ERROR state until the host issues a recovery
		 * command.  However, HEAD may have advanced past one or
		 * more already-completed transactions before the error
		 * occurred (their completion IRQ may not have been
		 * processed yet).  Retire those normally first, then
		 * force-complete the NEXT transaction (the one that
		 * actually failed) with -EIO.
		 *
		 * MBX command semantics after ERROR:
		 *   CONTINUE -- re-run the same VCQ at HEAD (retry)
		 *   RESTART  -- advance HEAD+1, skip failed, resume
		 *   FLUSH    -- HEAD=TAIL, flush all HWCs, discard queue
		 */

		/* First: retire transactions completed before the error */
		while ((txn = cmh_tm_peek_transaction(mbx_idx)) != NULL) {
			if ((s32)(new_head - txn->last_vcq_id) <= 0)
				break;
			txn = cmh_tm_pop_transaction(mbx_idx);
			if (!txn)
				break;
			dev_dbg(cmh_dev(),
				"rh: mbx[%u] pre-error complete vcq=%u..%u\n",
				mbx_idx, txn->first_vcq_id,
				txn->last_vcq_id);
			cmh_txn_finish(txn, 0);
			cmh_tm_txq_completion_notify();
		}

		/* Now pop and fail the transaction that actually errored */
		txn = cmh_tm_pop_transaction(mbx_idx);
		if (txn) {
			dev_dbg(cmh_dev(), "rh: mbx[%u] error-complete vcq=%u..%u\n",
				mbx_idx, txn->first_vcq_id,
				txn->last_vcq_id);
			cmh_txn_finish(txn, error);
			cmh_tm_txq_completion_notify();
		} else {
			u32 head_reg, tail_reg;

			head_reg = cmh_reg_read32(base, R_MBX_QUEUE_HEAD);
			tail_reg = cmh_reg_read32(base, R_MBX_QUEUE_TAIL);
			dev_warn_ratelimited(cmh_dev(),
					     "rh: mbx[%u] ERROR with empty txn queue (orphaned) status=0x%08x head=%u tail=%u core=%u ecode=%u cmd_idx=%u\n",
					     mbx_idx, status,
					     head_reg, tail_reg,
					     MBX_STATUS_CORE_ID(status),
					     MBX_STATUS_ERROR_CODE(status),
					     MBX_STATUS_CMD_INDEX(status));
		}
		{
			struct cmh_mbx_stats *s = cmh_debugfs_mbx_stats(mbx_idx);

			if (s)
				atomic64_inc(&s->vcqs_errors);
		}

		/*
		 * W1C-clear R_MBX_INTERRUPT before issuing RESTART.
		 *
		 * The eSW sets MBX_ERROR_IRQ in R_MBX_INTERRUPT when
		 * it writes ERROR status.  On platforms where the
		 * hardirq handler runs (IRQ wired to GIC), this bit
		 * is cleared there.  On polling-only platforms (no
		 * IRQ line), it must be cleared explicitly before
		 * issuing a recovery command to de-assert the
		 * MBX-to-SIC interrupt line.
		 */
		cmh_reg_write32(MBX_IRQ_MASK, base, R_MBX_INTERRUPT);
		cmh_reg_write32(MBX_COMMAND_RESTART, base, R_MBX_COMMAND);

		/*
		 * Poke R_MBX_QUEUE_TAIL to guarantee the eSW receives
		 * an interrupt.
		 *
		 * Writing R_MBX_COMMAND alone may not produce a new
		 * SIC interrupt edge if the MBX-to-SIC line is still
		 * asserted from prior error processing.  The eSW RUN
		 * handler re-writes ERROR_IRQ to R_MBX_INTERRUPT on
		 * every spurious wakeup while in ERROR state, which
		 * can keep the SIC line high on level-triggered HW.
		 *
		 * R_MBX_QUEUE_TAIL writes always generate a fresh
		 * interrupt to the eSW (this is the normal VCQ
		 * submission path).  Writing the current TAIL value
		 * back is a no-op from the queue perspective but
		 * ensures the eSW wakes from WFI and processes the
		 * RESTART command.
		 */
		cmh_rh_poke_tail(base);
		WRITE_ONCE(rh.mbx[mbx_idx].restart_pending, true);
		rh.mbx[mbx_idx].restart_retries = 0;
		return;
	}

	/*
	 * Pop completed transactions.  A transaction is complete when
	 * the CMH eSW has advanced head past its last VCQ ID:
	 *   (s32)(new_head - txn->last_vcq_id) > 0
	 * Using signed comparison for correct wrap-around handling.
	 *
	 * Multi-VCQ note: transactions spanning multiple slots (e.g.
	 * SLH-DSA with 3+ VCQs) are treated atomically -- either the
	 * head has passed all of them or none.  The CMH eSW processes
	 * multi-VCQ groups sequentially within a single mailbox and
	 * only advances HEAD after the entire group completes.  Per-slot
	 * progress validation (checking intermediate HEAD positions
	 * within a multi-VCQ group) is not implemented because:
	 *   1. The eSW guarantees atomic group completion semantics
	 *   2. Partial progress is only observable during processing,
	 *      never at a completion boundary
	 *   3. Adding intermediate checks would require tracking
	 *      per-slot status with no correctness benefit
	 *
	 * A defensive WARN_ON_ONCE detects eSW misbehavior: if HEAD
	 * lands between first_vcq_id and last_vcq_id of a multi-VCQ
	 * transaction, the eSW violated its atomic group contract.
	 */
	while ((txn = cmh_tm_peek_transaction(mbx_idx)) != NULL) {
		if ((s32)(new_head - txn->last_vcq_id) <= 0) {
			/*
			 * Not yet complete.  For multi-VCQ transactions,
			 * assert HEAD hasn't partially advanced into the
			 * group -- that would indicate eSW firmware bug.
			 */
			WARN_ON_ONCE(txn->first_vcq_id != txn->last_vcq_id &&
				     (s32)(new_head - txn->first_vcq_id) > 0);
			break;
		}

		txn = cmh_tm_pop_transaction(mbx_idx);
		if (!txn)
			break;

		dev_dbg(cmh_dev(), "rh: mbx[%u] complete vcq=%u..%u err=%d\n",
			mbx_idx, txn->first_vcq_id, txn->last_vcq_id,
			 error);

		{
			struct cmh_mbx_stats *s = cmh_debugfs_mbx_stats(mbx_idx);

			if (s) {
				u32 n = txn->last_vcq_id -
					txn->first_vcq_id + 1;

				atomic64_add(n, &s->vcqs_completed);
			}
		}

		cmh_txn_finish(txn, error);
		cmh_tm_txq_completion_notify();
	}
}

/*
 * Threaded IRQ handler -- runs in process context.
 *
 * Walk all MBXes that had pending interrupts.  After processing the
 * pending set, do a final hardware poll of all MBX head registers to
 * catch completions whose PLIC interrupt was consumed during an
 * earlier register access (e.g. an inline interrupt notification
 * during MMIO can cause the PLIC edge to be claimed before the
 * hardirq sees it).
 */
static irqreturn_t cmh_rh_thread(int irq, void *data)
{
	struct cmh_config *cfg = data;
	u32 i;
	bool recheck;

	do {
		recheck = false;

		for (i = 0; i < cfg->mbx_count; i++) {
			u32 new_head, irq_bits;

			if (!READ_ONCE(rh.mbx[i].pending))
				continue;

			irq_bits = (u32)atomic_xchg(&rh.mbx[i].irq_bits, 0);
			WRITE_ONCE(rh.mbx[i].pending, false);

			spin_lock_bh(&rh_process_lock);
			new_head = cmh_reg_read32(cfg->mailboxes[i].reg_base,
						  R_MBX_QUEUE_HEAD);

			if (new_head == rh.mbx[i].last_head && !irq_bits) {
				spin_unlock_bh(&rh_process_lock);
				continue;
			}

			cmh_rh_process_mbx(i, new_head, irq_bits);
			rh.mbx[i].last_head = new_head;
			spin_unlock_bh(&rh_process_lock);
		}

		/*
		 * Re-check: if the hardirq fired again while we were
		 * processing, pending flags will be set again.
		 */
		for (i = 0; i < cfg->mbx_count; i++) {
			if (READ_ONCE(rh.mbx[i].pending)) {
				recheck = true;
				break;
			}
		}
	} while (recheck);

	/*
	 * Final hardware poll: read every MBX head register and status
	 * to catch completions or errors whose interrupt was missed.
	 */
	for (i = 0; i < cfg->mbx_count; i++) {
		u32 new_head;
		u32 status;
		u32 poll_irq_bits = 0;

		spin_lock_bh(&rh_process_lock);
		new_head = cmh_reg_read32(cfg->mailboxes[i].reg_base,
					  R_MBX_QUEUE_HEAD);
		status = cmh_reg_read32(cfg->mailboxes[i].reg_base,
					R_MBX_STATUS);

		if (MBX_STATUS_CODE(status) == MBX_STATUS_ERROR) {
			if (READ_ONCE(rh.mbx[i].wedged)) {
				spin_unlock_bh(&rh_process_lock);
				continue;
			}
			if (READ_ONCE(rh.mbx[i].restart_pending)) {
				/*
				 * HEAD advanced while restart_pending means
				 * RESTART worked but next VCQ also failed.
				 * Clear restart state and process new error.
				 */
				if (new_head != rh.mbx[i].last_head) {
					WRITE_ONCE(rh.mbx[i].restart_pending,
						   false);
					rh.mbx[i].restart_retries = 0;
				} else {
					spin_unlock_bh(&rh_process_lock);
					continue;
				}
			}
			poll_irq_bits = MBX_ERROR_IRQ;
		} else {
			WRITE_ONCE(rh.mbx[i].restart_pending, false);
			rh.mbx[i].restart_retries = 0;
			rh.mbx[i].flush_count = 0;
		}

		if (new_head != rh.mbx[i].last_head || poll_irq_bits) {
			cmh_rh_process_mbx(i, new_head, poll_irq_bits);
			rh.mbx[i].last_head = new_head;
		}
		spin_unlock_bh(&rh_process_lock);
	}

	return IRQ_HANDLED;
}

/*
 * Watchdog timer callback -- missed-IRQ recovery.
 *
 * Reads all MBX head registers.  If any head advanced without a
 * corresponding IRQ, process the completions here.  Re-arms itself
 * while rh.active is true.
 */
static void cmh_rh_watchdog_fn(struct timer_list *t)
{
	u32 i;

	if (!rh.active || !rh.cfg || !rh.mbx)
		return;

	for (i = 0; i < rh.cfg->mbx_count; i++) {
		u32 new_head;
		u32 status;
		u32 irq_bits = 0;

		spin_lock(&rh_process_lock);
		new_head = cmh_reg_read32(rh.cfg->mailboxes[i].reg_base,
					  R_MBX_QUEUE_HEAD);
		status = cmh_reg_read32(rh.cfg->mailboxes[i].reg_base,
					R_MBX_STATUS);

		if (MBX_STATUS_CODE(status) == MBX_STATUS_ERROR) {
			if (READ_ONCE(rh.mbx[i].wedged)) {
				spin_unlock(&rh_process_lock);
				continue;
			}
			/*
			 * Back-to-back failure scenario: the crypto API
			 * (e.g. testmgr) may submit requests continuously.
			 * If RESTART succeeds but the next VCQ also fails,
			 * the entire RESTART->IDLE->RUN->ERROR cycle can
			 * complete within a single 200ms watchdog period.
			 * Without the HEAD-advance check below, the watchdog
			 * would mistake the new error for a failed RESTART,
			 * increment restart_retries, and eventually escalate
			 * to FLUSH -- wedging the mailbox unnecessarily.
			 */
			if (READ_ONCE(rh.mbx[i].restart_pending)) {
				void __iomem *base =
					rh.cfg->mailboxes[i].reg_base;

				/*
				 * HEAD advanced since RESTART was issued:
				 * RESTART succeeded, this is a fresh error.
				 * Clear recovery state and process normally.
				 */
				if (new_head != rh.mbx[i].last_head) {
					dev_dbg(cmh_dev(),
						"rh: watchdog: mbx[%u] head advanced %u->%u during restart -- new error\n",
						i, rh.mbx[i].last_head,
						new_head);
					WRITE_ONCE(rh.mbx[i].restart_pending,
						   false);
					rh.mbx[i].restart_retries = 0;
					goto new_error;
				}

				rh.mbx[i].restart_retries++;
				if (rh.mbx[i].restart_retries >
				    CMH_RH_RESTART_MAX_RETRIES) {
					rh.mbx[i].flush_count++;
					if (rh.mbx[i].flush_count >=
					    CMH_RH_FLUSH_MAX_FAILURES) {
						u32 hb, ei, cmd;

						cmd = cmh_reg_read32(base, R_MBX_COMMAND);
						hb = cmh_reg_read32(rh.cfg->sic_mapped,
								    R_SIC_SW_HEARTBEAT);
						ei = cmh_reg_read32(rh.cfg->sic_mapped,
								    R_SIC_SW_ERROR_INFO);
						dev_crit(cmh_dev(),
							 "rh: mbx[%u] wedged after %u FLUSHes (cmd=0x%x status=0x%x hb=0x%x err=0x%x)\n",
							 i,
							 rh.mbx[i].flush_count,
							 cmd, status,
							 hb, ei);
						WRITE_ONCE(rh.mbx[i].wedged,
							   true);
						cmh_rh_drain_mbx(i, -EIO);
						spin_unlock(&rh_process_lock);
						continue;
					}
					/*
					 * Backstop: eSW did not respond
					 * to RESTART within the retry
					 * budget.  Escalate to FLUSH
					 * which is a harder reset of
					 * the eSW mailbox state.
					 */
					dev_err(cmh_dev(),
						"rh: watchdog: mbx[%u] RESTART unresponsive after %u ticks, escalating to FLUSH (attempt %u/%u)\n",
						i, rh.mbx[i].restart_retries,
						rh.mbx[i].flush_count,
						CMH_RH_FLUSH_MAX_FAILURES);
					cmh_reg_write32(MBX_IRQ_MASK,
							base,
							R_MBX_INTERRUPT);
					cmh_reg_write32(MBX_COMMAND_FLUSH,
							base,
							R_MBX_COMMAND);
					cmh_rh_poke_tail(base);
					cmh_rh_drain_mbx(i, -EIO);
					WRITE_ONCE(rh.mbx[i].restart_pending,
						   false);
					rh.mbx[i].restart_retries = 0;
					spin_unlock(&rh_process_lock);
					continue;
				}
				/*
				 * RESTART was already issued on a prior
				 * tick but the eSW hasn't cleared the
				 * ERROR status yet.  Do NOT pop another
				 * transaction -- that would cascade-kill
				 * unrelated in-flight work.  Re-poke TAIL
				 * in case the eSW missed the interrupt.
				 */
				cmh_rh_poke_tail(base);
				dev_dbg_ratelimited(cmh_dev(),
						    "rh: watchdog: mbx[%u] restart pending (%u/%u) status=0x%08x, re-poke\n",
						    i,
						    rh.mbx[i].restart_retries,
						    CMH_RH_RESTART_MAX_RETRIES,
						    status);
				spin_unlock(&rh_process_lock);
				continue;
			}
new_error:
			dev_dbg_ratelimited(cmh_dev(),
					    "rh: watchdog: mbx[%u] error status=0x%08x (missed error IRQ) head=%u tail=%u core=%u ecode=%u cmd_idx=%u\n",
					    i, status, new_head,
					    cmh_reg_read32(rh.cfg->mailboxes[i].reg_base,
							   R_MBX_QUEUE_TAIL),
					    MBX_STATUS_CORE_ID(status),
					    MBX_STATUS_ERROR_CODE(status),
					    MBX_STATUS_CMD_INDEX(status));
			irq_bits = MBX_ERROR_IRQ;
		} else {
			/* eSW cleared ERROR -- recovery succeeded */
			WRITE_ONCE(rh.mbx[i].restart_pending, false);
			rh.mbx[i].restart_retries = 0;
			rh.mbx[i].flush_count = 0;
		}

		if (new_head != rh.mbx[i].last_head || irq_bits) {
			if (new_head != rh.mbx[i].last_head)
				dev_dbg_ratelimited(cmh_dev(),
						    "rh: watchdog: mbx[%u] head %u->%u (missed IRQ recovery)\n",
						    i, rh.mbx[i].last_head,
						    new_head);
			cmh_rh_process_mbx(i, new_head, irq_bits);
			rh.mbx[i].last_head = new_head;
			rh.mbx[i].abort_stall_ticks = 0;
		}

		/*
		 * Abort-stall detector: if the head-of-queue transaction
		 * timed out (state == TXN_TIMED_OUT) but the eSW hasn't
		 * responded (HEAD didn't advance, no ERROR status):
		 *
		 *   tick 1:        issue MBX_COMMAND_ABORT (serialised
		 *                  under rh_process_lock -- safe against
		 *                  concurrent RESTART/FLUSH)
		 *   ticks 2..N-1:  wait for eSW to respond with ERROR
		 *   tick N:         escalate to FLUSH + force-drain
		 *
		 * If the eSW responds with ERROR between ticks, the ERROR
		 * status branch above handles RESTART recovery and resets
		 * abort_stall_ticks via the restart_pending guard.
		 */
		if (!READ_ONCE(rh.mbx[i].wedged) &&
		    !READ_ONCE(rh.mbx[i].restart_pending)) {
			struct transaction_obj *head_txn;

			head_txn = cmh_tm_peek_transaction(i);
			if (head_txn &&
			    atomic_read(&head_txn->state) == TXN_TIMED_OUT) {
				unsigned int stall_max;
				void __iomem *base =
					rh.cfg->mailboxes[i].reg_base;

				rh.mbx[i].abort_stall_ticks++;

				if (rh.mbx[i].abort_stall_ticks == 1) {
					dev_warn(cmh_dev(),
						 "rh: watchdog: mbx[%u] head txn timed out, issuing ABORT\n",
						 i);
					cmh_reg_write32(MBX_COMMAND_ABORT,
							base,
							R_MBX_COMMAND);
				}

				stall_max = DIV_ROUND_UP(CMH_RH_ABORT_STALL_MS,
							 max(watchdog_ms,
							     CMH_RH_WATCHDOG_MS_MIN));
				if (rh.mbx[i].abort_stall_ticks >=
				    stall_max) {
					dev_err(cmh_dev(),
						"rh: watchdog: mbx[%u] abort stall (%u ticks) -- FLUSH + drain\n",
						i, rh.mbx[i].abort_stall_ticks);
					cmh_reg_write32(MBX_COMMAND_FLUSH,
							base, R_MBX_COMMAND);
					cmh_rh_drain_mbx(i, -ETIMEDOUT);
					rh.mbx[i].abort_stall_ticks = 0;
				}
			} else {
				rh.mbx[i].abort_stall_ticks = 0;
			}
		}
		spin_unlock(&rh_process_lock);
	}

	if (rh.active) {
		unsigned int wdog = max(watchdog_ms, CMH_RH_WATCHDOG_MS_MIN);

		mod_timer(&rh_watchdog,
			  jiffies + msecs_to_jiffies(wdog));
	}
}

/*
 * Resolve per-MBX Linux virqs for the CMH interrupt lines.
 *
 * Strategy:
 *   1. If cfg->irq >= 0, use it as a shared IRQ for all MBXes
 *   2. Otherwise, find the "cri,cmh" DT node and map one IRQ per
 *      active mailbox using cfg->mailboxes[i].instance as the DT
 *      interrupt index (matching the per-MBX PLIC wiring)
 *
 * Populates rh.irqs[] and rh.nirqs.  Returns 0 on success, or a
 * negative errno if no IRQs could be resolved (polling-only mode).
 */
static int cmh_rh_resolve_irqs(struct cmh_config *cfg)
{
	struct device_node *np;
	u32 i;

	rh.nirqs = 0;

	/* Single legacy IRQ from DT: shared across all MBXes */
	if (cfg->irq >= 0) {
		rh.irqs[0] = cfg->irq;
		rh.nirqs = 1;
		dev_dbg(cmh_dev(), "rh: using single DT IRQ %d for all %u MBXes\n",
			cfg->irq, cfg->mbx_count);
		return 0;
	}

	np = cfg->of_node;
	if (!np) {
		dev_warn(cmh_dev(), "rh: no DT node -- IRQ disabled\n");
		return -ENODEV;
	}

	for (i = 0; i < cfg->mbx_count; i++) {
		int dt_idx = cfg->mailboxes[i].instance;
		int virq = of_irq_get(np, dt_idx);

		if (virq <= 0) {
			dev_warn(cmh_dev(), "rh: failed to map IRQ for MBX%u (DT index %d, rc=%d)\n",
				 i, dt_idx, virq);
			return -ENODEV;
		}
		rh.irqs[i] = virq;
		dev_dbg(cmh_dev(), "rh: MBX%u -> IRQ %d (DT index %d)\n",
			i, virq, dt_idx);
	}

	rh.nirqs = cfg->mbx_count;
	return 0;
}

/**
 * cmh_rh_init() - Initialize the response handler
 * @cfg: Device configuration (mailbox count, MMIO bases, IRQ info)
 *
 * Resolve per-mailbox IRQs from the device tree (or module parameter
 * override), register threaded IRQ handlers (hardirq + kthread), and
 * arm the missed-IRQ software watchdog timer.  If no IRQs can be
 * resolved, falls back to watchdog-only polling mode.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_rh_init(struct cmh_config *cfg)
{
	int ret;
	u32 i;

	rh.cfg = cfg;
	rh.nirqs = 0;
	rh.active = false;
	atomic_set(&rh.irq_count, 0);

	/* Allocate per-MBX tracking */
	rh.mbx = kcalloc(cfg->mbx_count, sizeof(*rh.mbx), GFP_KERNEL);
	if (!rh.mbx)
		return -ENOMEM;

	/* Resolve per-MBX IRQs */
	if (cmh_rh_resolve_irqs(cfg) < 0) {
		/*
		 * No IRQs available.  The watchdog timer provides
		 * a polling fallback: it reads MBX head registers
		 * periodically and processes completions.  This is
		 * slower than IRQ-driven completion but functional.
		 *
		 * Completion latency in polling-only mode is bounded
		 * by the watchdog interval (default 200 ms, tunable
		 * via debugfs config/watchdog_ms).
		 */
		dev_warn(cmh_dev(),
			 "rh: no IRQs -- using watchdog polling (interval %u ms)\n",
			 watchdog_ms);

		/* Seed last_head from HW before first watchdog tick */
		for (i = 0; i < cfg->mbx_count; i++)
			rh.mbx[i].last_head =
				cmh_reg_read32(cfg->mailboxes[i].reg_base,
					       R_MBX_QUEUE_HEAD);

		rh.active = true;
		timer_setup(&rh_watchdog, cmh_rh_watchdog_fn, 0);
		mod_timer(&rh_watchdog, jiffies +
			  msecs_to_jiffies(max(watchdog_ms,
					       CMH_RH_WATCHDOG_MS_MIN)));
		return 0;
	}

	/* Initialize per-MBX state: read current head positions */
	for (i = 0; i < cfg->mbx_count; i++)
		rh.mbx[i].last_head = cmh_reg_read32(rh.cfg->mailboxes[i].reg_base,
						     R_MBX_QUEUE_HEAD);

	/*
	 * Register threaded IRQ handlers.
	 *
	 * DT per-MBX path: one distinct virq per MBX, nirqs == mbx_count.
	 * DT single-IRQ path: one shared IRQ, nirqs == 1.  The handler
	 * scans all mailboxes unconditionally, so a single registration
	 * suffices.
	 *
	 * Use IRQF_SHARED only for the single-IRQ path where one line
	 * is shared across all MBXes.  Dedicated per-MBX virqs need no
	 * sharing flag.
	 */
	{
		unsigned long irqflags = (rh.nirqs == 1 && cfg->mbx_count > 1)
					  ? IRQF_SHARED : 0;

		for (i = 0; i < rh.nirqs; i++) {
			ret = request_threaded_irq(rh.irqs[i],
						   cmh_rh_hardirq,
						   cmh_rh_thread,
						   irqflags,
						   "cmh", cfg);
			if (ret) {
				dev_err(cmh_dev(), "rh: request_threaded_irq(%d) for MBX%u failed (rc=%d)\n",
					rh.irqs[i], i, ret);
				/* Unwind previously registered IRQs */
				while (i--)
					free_irq(rh.irqs[i], cfg);
				rh.nirqs = 0;
				kfree(rh.mbx);
				rh.mbx = NULL;
				return ret;
			}
		}
	}

	rh.active = true;

	/* Enable MBX completion interrupts (DONE + ERROR) */
	for (i = 0; i < cfg->mbx_count; i++) {
		u32 stale;

		/*
		 * W1C any interrupt bits that accumulated between
		 * MQI setup and now (e.g. CMH eSW processing stale
		 * commands) before enabling the mask.
		 */
		stale = cmh_reg_read32(cfg->mailboxes[i].reg_base,
				       R_MBX_INTERRUPT);
		if (stale)
			cmh_reg_write32(stale, cfg->mailboxes[i].reg_base,
					R_MBX_INTERRUPT);

		cmh_reg_write32(MBX_IRQ_MASK,
				cfg->mailboxes[i].reg_base,
				R_MBX_INTERRUPT_MASK);
	}

	dev_info(cmh_dev(), "rh: initialized (%u IRQs, %u mailboxes, watchdog %u ms)\n",
		 rh.nirqs, cfg->mbx_count, watchdog_ms);

	/* Arm missed-IRQ watchdog timer */
	timer_setup(&rh_watchdog, cmh_rh_watchdog_fn, 0);
	mod_timer(&rh_watchdog, jiffies +
		  msecs_to_jiffies(max(watchdog_ms,
				       CMH_RH_WATCHDOG_MS_MIN)));

	return 0;
}

/**
 * cmh_rh_suspend() - Suspend the response handler
 * @cfg: Device configuration
 *
 * Stop the watchdog timer and mask mailbox interrupts at the hardware
 * level.  The IRQ handlers remain registered so that resume can
 * re-enable them without re-requesting.
 */
void cmh_rh_suspend(struct cmh_config *cfg)
{
	u32 i;

	if (!rh.active)
		return;

	/* Stop the watchdog before masking HW interrupts */
	timer_delete_sync(&rh_watchdog);

	/* Mask MBX interrupts at the hardware level */
	for (i = 0; i < cfg->mbx_count; i++)
		cmh_reg_write32(0, cfg->mailboxes[i].reg_base,
				R_MBX_INTERRUPT_MASK);

	/*
	 * Ensure no threaded IRQ handler is still in-flight.
	 * After masking, a handler may already have been scheduled.
	 * synchronize_irq() waits for it to complete before we
	 * proceed with suspend (which tears down TM state).
	 */
	for (i = 0; i < rh.nirqs; i++)
		synchronize_irq(rh.irqs[i]);

	rh.active = false;
	dev_dbg(cmh_dev(), "rh: suspended\n");
}

/**
 * cmh_rh_resume() - Resume the response handler after suspend
 * @cfg: Device configuration
 *
 * Re-synchronize per-mailbox head tracking with hardware, clear stale
 * interrupt bits accumulated during the power transition, re-enable
 * mailbox completion interrupts, and re-arm the watchdog timer.
 */
void cmh_rh_resume(struct cmh_config *cfg)
{
	u32 i;

	if (!rh.mbx || !cfg)
		return;

	/* Re-sync per-MBX head tracking with hardware */
	for (i = 0; i < cfg->mbx_count; i++) {
		u32 stale;

		rh.mbx[i].last_head =
			cmh_reg_read32(cfg->mailboxes[i].reg_base,
				       R_MBX_QUEUE_HEAD);

		/* W1C any stale interrupt bits from the power transition */
		stale = cmh_reg_read32(cfg->mailboxes[i].reg_base,
				       R_MBX_INTERRUPT);
		if (stale)
			cmh_reg_write32(stale, cfg->mailboxes[i].reg_base,
					R_MBX_INTERRUPT);

		/* Re-enable MBX completion interrupts */
		cmh_reg_write32(MBX_IRQ_MASK, cfg->mailboxes[i].reg_base,
				R_MBX_INTERRUPT_MASK);
	}

	rh.active = true;

	/* Re-arm the watchdog */
	mod_timer(&rh_watchdog, jiffies +
		  msecs_to_jiffies(max(watchdog_ms,
				       CMH_RH_WATCHDOG_MS_MIN)));
	dev_dbg(cmh_dev(), "rh: resumed\n");
}

/**
 * cmh_rh_cleanup() - Clean up the response handler
 * @cfg: Device configuration
 *
 * Stop the watchdog timer, mask mailbox interrupts at the hardware
 * level, release all registered IRQ handlers, and free per-mailbox
 * tracking state.  Safe to call even if init was never completed.
 */
void cmh_rh_cleanup(struct cmh_config *cfg)
{
	if (rh.active) {
		u32 i;

		/* Cancel watchdog before disabling interrupts */
		timer_delete_sync(&rh_watchdog);

		/* Disable MBX interrupts before releasing handlers */
		for (i = 0; i < cfg->mbx_count; i++)
			cmh_reg_write32(0,
					cfg->mailboxes[i].reg_base,
					R_MBX_INTERRUPT_MASK);

		/* Release all per-MBX IRQs */
		for (i = 0; i < rh.nirqs; i++)
			free_irq(rh.irqs[i], cfg);
		dev_dbg(cmh_dev(), "rh: %u IRQs released\n", rh.nirqs);
		rh.nirqs = 0;
		rh.active = false;
	}

	dev_dbg(cmh_dev(), "rh: %u IRQs handled\n",
		atomic_read(&rh.irq_count));

	kfree(rh.mbx);
	rh.mbx = NULL;

	dev_info(cmh_dev(), "rh: cleaned up\n");
}

/* -- debugfs timeout accessor ------------------------------------------ */

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
/**
 * cmh_rh_timeout_watchdog_ptr() - Return pointer to watchdog_ms for debugfs
 *
 * Exposes the Response Handler watchdog timeout for runtime tuning
 * via debugfs config/ directory.
 *
 * Return: pointer to the static watchdog_ms variable.
 */
unsigned int *cmh_rh_timeout_watchdog_ptr(void) { return &watchdog_ms; }
#endif
