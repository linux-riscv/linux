// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Hardware RNG (DRBG) Driver
 *
 * Implements a Linux hwrng backed by the CMH DRBG core.  Each .read()
 * builds a 3-entry VCQ (header + GENERATE + FLUSH) and submits it
 * synchronously through the Transaction Manager.
 *
 * DRBG configuration (CONFIG) is a management-host operation in the
 * CMH security model.  The driver attempts CONFIG at probe with the
 * hardcoded ratio/strength defaults; this succeeds in stateless mode
 * (any host may CONFIG) or when this host is the management host.  On
 * -EPERM the driver logs a notice and continues -- GENERATE works once
 * the management host configures the DRBG.
 *
 * The management host (or any privileged user-space process) can also
 * reconfigure the DRBG at runtime via CMH_IOCTL_DRBG_CONFIG.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include "cmh_rng.h"
#include "cmh_vcq.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_sys.h"
#include "cmh_config.h"

/* VCQ layout for .read(): header + GENERATE + FLUSH = 3 entries. */
#define DRBG_READ_VCQ_CMDS	3

/* VCQ layout for CONFIG: header + RESET + CONFIG + FLUSH = 4 entries. */
#define DRBG_CONFIG_VCQ_CMDS	4

/*
 * DRBG parameters -- hardcoded to production defaults.
 * Entropy ratio 0 = 1:1 (full entropy), security strength 0x10 = 256-bit.
 */
#define CMH_DRBG_ENTROPY_RATIO		0
#define CMH_DRBG_SECURITY_STRENGTH	0x10

static unsigned int drbg_timeout_ms = 500;

/* VCQ Builders */

static void vcq_add_drbg_generate(struct vcq_cmd *slot, u64 dst_phys, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_DRBG, 0, 1, DRBG_CMD_GENERATE);
	slot->hwc.drbg.cmd_generate.dst = dst_phys;
	slot->hwc.drbg.cmd_generate.len = len;
}

/*
 * Maximum bytes per DRBG GENERATE request.  The kernel calls .read()
 * repeatedly to fill larger requests, so capping here is safe.
 * 32 bytes matches the 256-bit security strength natural output size.
 */
#define CMH_DRBG_MAX_GENERATE	32U
/* Backoff before re-issuing a blocking read after a transient DRBG error. */
#define CMH_DRBG_RETRY_BACKOFF_MS	20U

/* hwrng .read() callback */

static int cmh_rng_read(struct hwrng *rng, void *data, size_t max, bool wait)
{
	struct cmh_dma_orphan *orphan;
	struct vcq_cmd vcq[DRBG_READ_VCQ_CMDS];
	dma_addr_t dma_addr;
	void *dmabuf;
	size_t nbytes;
	int ret;

	if (max == 0)
		return 0;

	/*
	 * Our path uses GFP_KERNEL allocations and synchronous VCQ
	 * submission -- both may sleep.  When the caller indicates
	 * non-blocking context (!wait), return 0 ("no data yet") so
	 * the hwrng core retries later.
	 */
	if (!wait)
		return 0;

	nbytes = min_t(size_t, max, CMH_DRBG_MAX_GENERATE);

	orphan = kmalloc_obj(*orphan, GFP_KERNEL);
	if (!orphan)
		return -ENOMEM;

	dmabuf = kmalloc(nbytes, GFP_KERNEL);
	if (!dmabuf) {
		kfree(orphan);
		return -ENOMEM;
	}

	dma_addr = cmh_dma_map_single(dmabuf, nbytes, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(dma_addr)) {
		kfree(dmabuf);
		kfree(orphan);
		return -ENOMEM;
	}

	orphan->buf  = dmabuf;
	orphan->addr = dma_addr;
	orphan->len  = nbytes;
	orphan->dir  = DMA_FROM_DEVICE;

	vcq_set_header(&vcq[0], DRBG_READ_VCQ_CMDS);
	vcq_add_drbg_generate(&vcq[1], dma_addr, nbytes);
	vcq_add_flush(&vcq[2], CORE_ID_DRBG);

	/*
	 * Use the noabort variant: if the MBX is occupied by a slow
	 * operation (e.g. SLH-DSA sign at 120 s), we must not issue
	 * MBX_COMMAND_ABORT -- that would kill the unrelated in-flight
	 * VCQ.  On timeout with an in-flight VCQ (-EINPROGRESS), the
	 * orphan callback defers DMA cleanup until the RH fires.
	 */
	ret = cmh_tm_submit_sync_noabort(vcq, DRBG_READ_VCQ_CMDS, 1,
					 msecs_to_jiffies(drbg_timeout_ms),
					 cmh_dma_orphan_free, orphan);
	if (ret == -EINPROGRESS) {
		/*
		 * The orphan callback owns dmabuf and frees it on VCQ
		 * completion.  Return 0 (not -EAGAIN): .read() only runs with
		 * wait=true (see the !wait early return above), and the hwrng
		 * core forwards a negative errno straight to a blocking read
		 * whereas a 0 return makes it retry.
		 */
		return 0;
	}

	/* Normal path or cancelled-from-queue: caller owns DMA */
	cmh_dma_unmap_single(dma_addr, nbytes, DMA_FROM_DEVICE);
	kfree(orphan);

	if (ret) {
		/*
		 * .read() only runs with wait=true (see the !wait early
		 * return above).  For known transient conditions return 0 so
		 * the hwrng core retries the blocking read; a negative errno
		 * here would be forwarded to userspace on a blocking fd
		 * (e.g. -EAGAIN violates POSIX).  Propagate genuinely
		 * unexpected failures so real faults are not masked into an
		 * indefinite retry loop.
		 */
		switch (ret) {
		case -EAGAIN:
		case -EBUSY:
		case -ETIMEDOUT:
		case -EIO:
		/*
		 * -ENODEV: the TM is not running -- occurs when the
		 * hwrng kthread (PF_NOFREEZE, not frozen during
		 * suspend) calls .read() while the device is suspended.
		 * Treat as transient: the TM restarts on resume.
		 */
		case -ENODEV:
			dev_dbg_ratelimited(cmh_dev(),
					    "rng: transient DRBG failure (rc=%d)\n",
					    ret);
			kfree_sensitive(dmabuf);
			/*
			 * Back off before the hwrng core re-issues the
			 * blocking read: rng_dev_read() loops on a 0 return
			 * with only a conditional need_resched, so a persistent
			 * transient fault would otherwise spin the CPU.
			 */
			msleep(CMH_DRBG_RETRY_BACKOFF_MS);
			return 0;
		default:
			dev_err_ratelimited(cmh_dev(),
					    "rng: DRBG generate failed (rc=%d)\n",
					    ret);
			kfree_sensitive(dmabuf);
			return ret;
		}
	}

	memcpy(data, dmabuf, nbytes);
	kfree_sensitive(dmabuf);

	return nbytes;
}

/* Registration */

static bool cmh_rng_registered;

static struct hwrng cmh_hwrng = {
	.name = "rambus-cmh-drbg",
	.read = cmh_rng_read,
};

/**
 * cmh_rng_register() - Register the CMH hardware RNG device
 * @pdev: Platform device for the CMH accelerator
 *
 * Attempt a DRBG CONFIG VCQ (best effort; -EPERM when not the management
 * host is non-fatal), then register the hwrng device with the kernel
 * hwrng framework.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_rng_register(struct platform_device *pdev)
{
	struct vcq_cmd cfg_vcq[DRBG_CONFIG_VCQ_CMDS];
	int ret;

	/*
	 * The hwrng core elevates a zero quality to full trust (1024) for
	 * a hardware RNG, so cmh_hwrng.quality is left at 0.  Set it in the
	 * hwrng initializer to lower the entropy estimate if a platform
	 * requires it.
	 *
	 * DRBG CONFIG is a management-host operation.  Attempt it: it
	 * succeeds in stateless mode (any host) or when we are the
	 * management host.  On -EPERM (not the management host) continue
	 * without error -- GENERATE works once the management host has
	 * configured the DRBG.
	 */
	vcq_set_header(&cfg_vcq[0], DRBG_CONFIG_VCQ_CMDS);
	vcq_add_drbg_reset(&cfg_vcq[1]);
	vcq_add_drbg_config(&cfg_vcq[2], CMH_DRBG_ENTROPY_RATIO,
			    CMH_DRBG_SECURITY_STRENGTH);
	vcq_add_flush(&cfg_vcq[3], CORE_ID_DRBG);
	ret = cmh_tm_submit_sync(cfg_vcq, DRBG_CONFIG_VCQ_CMDS, 1);
	if (ret == -EPERM)
		dev_notice(&pdev->dev,
			   "rng: DRBG config not permitted (not management host); assuming external configuration\n");
	else if (ret)
		dev_warn(&pdev->dev,
			 "rng: DRBG config failed (rc=%d)\n", ret);

	ret = hwrng_register(&cmh_hwrng);
	if (ret) {
		dev_err(&pdev->dev, "rng: hwrng_register failed (rc=%d)\n",
			ret);
		return ret;
	}

	cmh_rng_registered = true;
	return 0;
}

/**
 * cmh_rng_unregister() - Unregister the CMH hardware RNG device
 *
 * Unregisters the hwrng device from the kernel hwrng framework if it
 * was previously registered.
 */
void cmh_rng_unregister(void)
{
	if (!cmh_rng_registered)
		return;
	hwrng_unregister(&cmh_hwrng);
	cmh_rng_registered = false;
}

/* -- debugfs timeout accessor ------------------------------------------ */

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
/**
 * cmh_rng_timeout_drbg_ptr() - Return pointer to drbg_timeout_ms for debugfs
 *
 * Exposes the DRBG operation timeout for runtime tuning via debugfs
 * config/ directory.
 *
 * Return: pointer to the static drbg_timeout_ms variable.
 */
unsigned int *cmh_rng_timeout_drbg_ptr(void) { return &drbg_timeout_ms; }
#endif
