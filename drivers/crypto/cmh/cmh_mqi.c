// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Mailbox Queue Initializer
 *
 * Responsibilities:
 *   - Allocate queue buffers for each configured mailbox
 *   - Execute the MBX lock/setup/enable register sequence
 *   - Readback-verify all critical register writes
 *   - Hold lock for MBX lifetime (CMH eSW requires it for host access)
 *   - Clean up (flush + unlock + free) on exit or error
 *
 * Register sequence per instance (per CMH MBX hardware specification):
 *   1. Read R_MBX_LOCK -> non-zero = ownership token acquired
 *   2. W1C stale R_MBX_INTERRUPT bits (avoids spurious error cascade)
 *   3. Set R_MBX_INTERRUPT_MASK = MBX_IRQ_MASK
 *   4. Write QUEUE_LO/HI, SLOTS, STRIDE (queue address + geometry)
 *   5. Sync TAIL = HEAD (CMH eSW owns HEAD; avoids stale-queue parse)
 *   6. Readback verify QUEUE_LO/HI/SLOTS/STRIDE
 *   7. Write HOST_INFO (signals CMH eSW "MBX configured")
 *   8. Write COMMAND = MBX_COMMAND_RUN
 *   9. Lock stays held -- released only in teardown
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/io.h>
#include <linux/iopoll.h>

#include "cmh_mqi.h"
#include "cmh_dma.h"
#include "cmh_registers.h"
#include "cmh_config.h"

/* Flush polling: eSW clears R_MBX_COMMAND to 0 when flush completes */
#define MBX_FLUSH_POLL_US	50
#define MBX_FLUSH_TIMEOUT_US	1000000	/* 1 second */

/* MBX Lock / Unlock */

/*
 * Attempt to acquire the MBX hardware lock.
 * Returns the lock token (non-zero) on success, 0 on timeout.
 */
static u32 cmh_mbx_lock(void __iomem *reg_base, u32 instance)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(MBX_LOCK_TIMEOUT_MS);
	u32 lock;

	while (time_before(jiffies, deadline)) {
		lock = cmh_reg_read32(reg_base, R_MBX_LOCK);
		if (lock) {
			dev_dbg(cmh_dev(), "mbx %u lock acquired (token=0x%08x)\n",
				instance, lock);
			return lock;
		}
		/* HW lock may be held by CMH eSW -- back off before retry */
		usleep_range(MBX_LOCK_POLL_MIN_US, MBX_LOCK_POLL_MAX_US);
	}

	return 0;
}

/* Release the MBX lock: clear interrupt mask, write token back */
static void cmh_mbx_unlock(void __iomem *reg_base, u32 lock_val)
{
	cmh_reg_write32(0, reg_base, R_MBX_INTERRUPT_MASK);
	cmh_reg_write32(lock_val, reg_base, R_MBX_LOCK);
}

/* Register Readback Verification */

static int cmh_verify_reg(void __iomem *base, u32 offset, u32 expected,
			  const char *name, u32 instance)
{
	u32 actual = cmh_reg_read32(base, offset);

	if (actual != expected) {
		dev_err(cmh_dev(), "mbx %u %s readback mismatch: 0x%08x != 0x%08x\n",
			instance, name, actual, expected);
		return -EIO;
	}
	return 0;
}

/* Clear any stale interrupt bits left from a prior module lifecycle. */
static void cmh_mbx_clear_stale_irqs(void __iomem *base, u32 instance)
{
	u32 stale = cmh_reg_read32(base, R_MBX_INTERRUPT);

	if (stale) {
		cmh_reg_write32(stale, base, R_MBX_INTERRUPT);
		dev_dbg(cmh_dev(), "mbx %u cleared stale irq bits=0x%x\n",
			instance, stale);
	}
}

/* Read CMH eSW HEAD and set TAIL = HEAD so the queue appears empty. */
static void cmh_mbx_sync_tail_to_head(void __iomem *base, u32 instance)
{
	u32 fw_head = cmh_reg_read32(base, R_MBX_QUEUE_HEAD);

	cmh_reg_write32(fw_head, base, R_MBX_QUEUE_TAIL);
	if (fw_head)
		dev_dbg(cmh_dev(), "mbx %u synced tail=%u to fw head\n",
			instance, fw_head);
}

/* Per-Mailbox Setup */

static int cmh_mbx_setup_one(struct cmh_mbx_config *mbx)
{
	void __iomem *base = mbx->reg_base;
	u32 addr_lo = lower_32_bits(mbx->dma_handle);
	u32 addr_hi = upper_32_bits(mbx->dma_handle);
	u32 lock_val;
	int ret;

	/* Step 1: Acquire exclusive access */
	lock_val = cmh_mbx_lock(base, mbx->instance);
	if (!lock_val) {
		dev_err(cmh_dev(), "mbx %u lock timeout after %u ms\n",
			mbx->instance, MBX_LOCK_TIMEOUT_MS);
		return -ETIMEDOUT;
	}

	/*
	 * Step 1.5: Clear stale interrupt bits from a prior module lifecycle.
	 *
	 * After rmmod, the CMH eSW may leave ERROR_IRQ set in
	 * R_MBX_INTERRUPT even though STATUS is IDLE.  If we enable
	 * the mask first, the stale bits immediately trigger the
	 * CMH eSW interrupt chain, which can cascade into ERROR
	 * status before the first hash operation.  W1C-clear them first.
	 */
	cmh_mbx_clear_stale_irqs(base, mbx->instance);

	/* Step 2: Program interrupt mask (enable DONE/ERROR interrupts) */
	cmh_reg_write32(MBX_IRQ_MASK, base, R_MBX_INTERRUPT_MASK);

	/* Step 3: Configure queue address (64-bit split) */
	cmh_reg_write32(addr_lo, base, R_MBX_QUEUE_LO);
	cmh_reg_write32(addr_hi, base, R_MBX_QUEUE_HI);

	/* Step 4: Configure queue geometry */
	cmh_reg_write32(mbx->slots_log2, base, R_MBX_QUEUE_SLOTS);
	cmh_reg_write32(mbx->stride_log2, base, R_MBX_QUEUE_STRIDE);

	/*
	 * Step 5: Synchronise TAIL to CMH eSW's HEAD.
	 *
	 * R_MBX_QUEUE_HEAD is read-only from the host side -- only the
	 * CMH eSW can write it.  On a fresh boot HEAD is 0; after an
	 * rmmod/insmod cycle it retains the value from the previous
	 * session (e.g. 44).  Writing 0 from the host is silently
	 * dropped by the MBX HW.
	 *
	 * If we set TAIL=0 while HEAD=44 the CMH eSW sees a non-empty
	 * queue (head != tail with wrap-around) and immediately tries
	 * to load a VCQ at the old head offset into our freshly-zeroed
	 * DMA buffer, causing an "Invalid VCQ" EFAULT -> ECHILD cascade.
	 *
	 * Fix: read HEAD and set TAIL = HEAD so the queue looks empty.
	 */
	cmh_mbx_sync_tail_to_head(base, mbx->instance);

	/*
	 * Step 6: Readback verify critical registers.
	 * HOST_INFO is deliberately deferred to after verification -- writing
	 * it tells the CMH eSW "MBX is ready" and the CMH eSW may inspect
	 * (and clear) the queue registers immediately.
	 */
	ret = cmh_verify_reg(base, R_MBX_QUEUE_LO, addr_lo,
			     "QUEUE_LO", mbx->instance);
	if (ret)
		goto err_unlock;

	ret = cmh_verify_reg(base, R_MBX_QUEUE_HI, addr_hi,
			     "QUEUE_HI", mbx->instance);
	if (ret)
		goto err_unlock;

	ret = cmh_verify_reg(base, R_MBX_QUEUE_SLOTS, mbx->slots_log2,
			     "QUEUE_SLOTS", mbx->instance);
	if (ret)
		goto err_unlock;

	ret = cmh_verify_reg(base, R_MBX_QUEUE_STRIDE, mbx->stride_log2,
			     "QUEUE_STRIDE", mbx->instance);
	if (ret)
		goto err_unlock;

	/*
	 * Step 7: Host identification -- signals CMH eSW that MBX is configured.
	 * Must come after readback verification (CMH eSW may inspect the MBX
	 * immediately) and before COMMAND_RUN.
	 */
	cmh_reg_write32(MBX_HOST_INFO_LKM, base, R_MBX_HOST_INFO);

	/* Step 8: Enable -- start the mailbox */
	cmh_reg_write32(MBX_COMMAND_RUN, base, R_MBX_COMMAND);

	/* Read status while we still hold the lock */
	dev_dbg(cmh_dev(), "mbx %u setup: dma=0x%08x%08x slots=%u stride=%u status=0x%08x\n",
		mbx->instance, addr_hi, addr_lo,
		 mbx->slots_log2, mbx->stride_log2,
		 cmh_reg_read32(base, R_MBX_STATUS));

	/*
	 * Lock stays held for the lifetime of this MBX session.
	 *
	 * mbx->lock_val is the ownership token returned by R_MBX_LOCK at
	 * acquisition time.  The CMH eSW validates this token on every
	 * register access and requires it to be written back to release.
	 * It is NOT a transient mutex -- it persists until teardown.
	 */
	mbx->lock_val = lock_val;

	return 0;

err_unlock:
	cmh_mbx_unlock(base, lock_val);
	return ret;
}

/* Per-Mailbox Teardown */

static void cmh_mbx_teardown_one(struct cmh_mbx_config *mbx)
{
	void __iomem *base = mbx->reg_base;
	u32 status;

	if (!base || !mbx->lock_val)
		return;

	if (MBX_STATUS_CODE(cmh_reg_read32(base, R_MBX_STATUS)) !=
	    MBX_STATUS_OFFLINE) {
		cmh_reg_write32(MBX_COMMAND_FLUSH, base, R_MBX_COMMAND);

		/*
		 * Wait for the eSW to process the flush before releasing
		 * the DMA buffer.  The eSW clears R_MBX_COMMAND to zero
		 * upon completion; if it doesn't within 1 s, log a
		 * warning and proceed (best-effort teardown).
		 *
		 * DMA safety: by this point the RH and TM are already
		 * shut down (remove order: algos -> RH -> TM -> MQI),
		 * so no new transactions can be submitted and no
		 * completions are in flight.  The queue buffer is only
		 * read by the eSW during active command processing;
		 * after flush the eSW will not touch it again.
		 */
		if (read_poll_timeout(cmh_reg_read32, status,
				      status == 0,
				      MBX_FLUSH_POLL_US,
				      MBX_FLUSH_TIMEOUT_US,
				      true, base, R_MBX_COMMAND))
			dev_warn(cmh_dev(),
				 "mbx %u flush timeout during teardown (status=0x%08x)\n",
				 mbx->instance,
				 cmh_reg_read32(base, R_MBX_STATUS));
	}

	cmh_mbx_unlock(base, mbx->lock_val);
	mbx->lock_val = 0;
}

/* Public Interface */

/**
 * cmh_mqi_init() - Initialize all mailbox queues
 * @cfg: CMH configuration describing the mailboxes to set up
 *
 * Allocates DMA queue buffers for each configured mailbox, then executes
 * the MBX lock/setup/enable register sequence.  On failure, all
 * successfully initialized mailboxes are torn down and buffers freed.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mqi_init(struct cmh_config *cfg)
{
	unsigned int i, j;
	int ret;

	/* Allocate queue buffers */
	for (i = 0; i < cfg->mbx_count; i++) {
		struct cmh_mbx_config *m = &cfg->mailboxes[i];

		m->virt_addr = cmh_dma_alloc(m->queue_size, &m->dma_handle,
					     GFP_KERNEL);
		if (!m->virt_addr) {
			ret = -ENOMEM;
			goto err_free_bufs;
		}

		dev_dbg(cmh_dev(), "mqi[%u] alloc %zu bytes @ virt=%pK dma=%pad\n",
			i, m->queue_size, m->virt_addr, &m->dma_handle);
	}

	/* Lock/setup/enable each mailbox */
	for (i = 0; i < cfg->mbx_count; i++) {
		ret = cmh_mbx_setup_one(&cfg->mailboxes[i]);
		if (ret) {
			dev_err(cmh_dev(), "mqi[%u] setup failed (rc=%d)\n",
				i, ret);
			goto err_teardown;
		}
	}

	dev_info(cmh_dev(), "MQI init complete (%u mailboxes)\n", cfg->mbx_count);
	return 0;

err_teardown:
	for (j = 0; j < i; j++)
		cmh_mbx_teardown_one(&cfg->mailboxes[j]);
err_free_bufs:
	for (j = 0; j < cfg->mbx_count; j++) {
		if (cfg->mailboxes[j].virt_addr)
			cmh_dma_free(cfg->mailboxes[j].queue_size,
				     cfg->mailboxes[j].virt_addr,
				     cfg->mailboxes[j].dma_handle);
		cfg->mailboxes[j].virt_addr = NULL;
		cfg->mailboxes[j].dma_handle = 0;
	}
	return ret;
}

/**
 * cmh_mqi_cleanup() - Clean up all mailbox queues
 * @cfg: CMH configuration describing the mailboxes to tear down
 *
 * Tears down each mailbox (flush + unlock) and frees the DMA queue
 * buffers allocated by cmh_mqi_init().
 */
void cmh_mqi_cleanup(struct cmh_config *cfg)
{
	unsigned int i;

	for (i = 0; i < cfg->mbx_count; i++) {
		struct cmh_mbx_config *m = &cfg->mailboxes[i];

		cmh_mbx_teardown_one(m);

		if (m->virt_addr)
			cmh_dma_free(m->queue_size, m->virt_addr,
				     m->dma_handle);
		m->virt_addr = NULL;
		m->dma_handle = 0;
	}

	dev_info(cmh_dev(), "MQI cleanup complete\n");
}
