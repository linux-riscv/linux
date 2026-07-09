// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- debugfs Per-MBX Counters and Fault Injection
 *
 * Creates the /sys/kernel/debug/cmh/ tree with:
 *   mbxN/vcqs_submitted   (ro) Total VCQs sent to MBX N
 *   mbxN/vcqs_completed   (ro) Total completions received
 *   mbxN/vcqs_errors      (ro) Total error completions
 *   mbxN/queue_full_count (ro) Times select_mailbox() skipped this MBX
 *   mbxN/max_queue_depth  (ro) High-water mark of in-flight transactions
 *   mbxN/inject_abort     (wo) Write any value to inject MBX_COMMAND_ABORT
 *   mbxN/force_drain      (wo) Write any value to force-drain all pending txns
 *   tm/cmq_posts          (ro) Total cmh_tm_post_command() calls
 *   tm/cmq_depth_max      (ro) High-water mark of CMQ length
 *   tm/cmq_eagain_count   (ro) Times CMQ was full (-EAGAIN)
 *   tm/backoff_count      (ro) Times TM backed off (all MBX queues full)
 *   tm/async_timeout_count (ro) Async requests that timed out
 *
 * This file is only compiled when CONFIG_CRYPTO_DEV_CMH_DEBUG=y (see Kbuild).
 * Requires CONFIG_DEBUG_FS=y in the kernel (standard for dev builds).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/slab.h>

#include "cmh_debugfs.h"
#include "cmh_config.h"
#include "cmh_registers.h"
#include "cmh_dma.h"
#include "cmh_txn.h"
#include "cmh_rh.h"
#include "cmh_rng.h"

/* -- Module State ---------------------------------------------------------- */

static struct {
	struct dentry		*root;		/* /sys/kernel/debug/cmh/ */
	struct cmh_mbx_stats	*mbx;		/* array[mbx_count] */
	struct cmh_tm_stats	 tm;
	struct cmh_config	*cfg;		/* for inject_abort register access */
	u32			 mbx_count;
} dbgfs;

/* -- debugfs file ops for atomic64_t --------------------------------------- */

static int cmh_dbgfs_u64_get(void *data, u64 *val)
{
	*val = (u64)atomic64_read((atomic64_t *)data);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(cmh_dbgfs_u64_ro_fops,
			 cmh_dbgfs_u64_get, NULL, "%llu\n");

/* -- Per-MBX directory ----------------------------------------------------- */

/*
 * inject_abort -- write-only debugfs file for fault injection.
 *
 * Writing any value triggers MBX_COMMAND_ABORT on this mailbox.
 * The eSW calls mbx_abort() -> mbx_cmd_error(mbx, -EPIPE), fires the
 * error IRQ, and the LKM RH completes in-flight transactions with -EIO
 * then issues MBX_COMMAND_RESTART to resume the mailbox.
 *
 * Private data points to the MBX index (cast to void *).
 */
static ssize_t inject_abort_write(struct file *file,
				  const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	u32 idx = (u32)(unsigned long)file->private_data;
	void __iomem *base;

	if (!dbgfs.cfg || idx >= dbgfs.cfg->mbx_count)
		return -EINVAL;

	base = dbgfs.cfg->mailboxes[idx].reg_base;
	dev_warn(cmh_dev(), "debugfs: injecting ABORT on mbx[%u]\n", idx);
	cmh_reg_write32(MBX_COMMAND_ABORT, base, R_MBX_COMMAND);

	return count;
}

static const struct file_operations inject_abort_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = inject_abort_write,
	.llseek = noop_llseek,
};

/*
 * force_drain -- write-only debugfs file for administrative recovery.
 *
 * Writing any value issues MBX_COMMAND_FLUSH, drains all pending
 * transactions on this mailbox (completing each with -ECANCELED),
 * and resets all recovery bookkeeping (abort_stall_ticks,
 * restart_pending, restart_retries, flush_count, wedged).
 *
 * Use this to recover D-state processes when the eSW is dead and
 * normal ABORT/RESTART escalation has not recovered the mailbox.
 */
static ssize_t force_drain_write(struct file *file,
				 const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	u32 idx = (u32)(unsigned long)file->private_data;

	if (!dbgfs.cfg || idx >= dbgfs.cfg->mbx_count)
		return -EINVAL;

	cmh_rh_force_drain_mbx(idx);
	return count;
}

static const struct file_operations force_drain_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = force_drain_write,
	.llseek = noop_llseek,
};

static void create_mbx_dir(u32 idx, struct dentry *parent)
{
	struct cmh_mbx_stats *s = &dbgfs.mbx[idx];
	struct dentry *d;
	char name[16];

	snprintf(name, sizeof(name), "mbx%u", idx);
	d = debugfs_create_dir(name, parent);

	debugfs_create_file("vcqs_submitted",   0444, d,
			    &s->vcqs_submitted,   &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("vcqs_completed",   0444, d,
			    &s->vcqs_completed,   &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("vcqs_errors",      0444, d,
			    &s->vcqs_errors,      &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("queue_full_count", 0444, d,
			    &s->queue_full_count, &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("max_queue_depth",  0444, d,
			    &s->max_queue_depth,  &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("inject_abort",     0200, d,
			    (void *)(uintptr_t)idx, &inject_abort_fops);
	debugfs_create_file("force_drain",      0200, d,
			    (void *)(uintptr_t)idx, &force_drain_fops);
}

/* -- TM directory ---------------------------------------------------------- */

static void create_tm_dir(struct dentry *parent)
{
	struct cmh_tm_stats *s = &dbgfs.tm;
	struct dentry *d;

	d = debugfs_create_dir("tm", parent);

	debugfs_create_file("cmq_posts",        0444, d,
			    &s->cmq_posts,        &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("cmq_depth_max",    0444, d,
			    &s->cmq_depth_max,    &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("cmq_eagain_count", 0444, d,
			    &s->cmq_eagain_count, &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("backoff_count",    0444, d,
			    &s->backoff_count,    &cmh_dbgfs_u64_ro_fops);
	debugfs_create_file("async_timeout_count", 0444, d,
			    &s->async_timeout_count, &cmh_dbgfs_u64_ro_fops);
}

/* -- Config directory: timeout tuning ---------------------------------- */

static void create_config_dir(struct dentry *parent)
{
	struct dentry *d;

	d = debugfs_create_dir("config", parent);

	/* TM timeouts */
	debugfs_create_u32("async_timeout_ms",   0644, d,
			   cmh_tm_timeout_async_ptr());
	debugfs_create_u32("vcq_timeout_ms",     0644, d,
			   cmh_tm_timeout_vcq_ptr());
	debugfs_create_u32("slow_op_timeout_ms", 0644, d,
			   cmh_tm_timeout_slow_op_ptr());
	debugfs_create_u32("drain_timeout_ms",   0644, d,
			   cmh_tm_timeout_drain_ptr());

	/* RH watchdog */
	debugfs_create_u32("watchdog_ms",        0644, d,
			   cmh_rh_timeout_watchdog_ptr());

	/* DRBG timeout */
	debugfs_create_u32("drbg_timeout_ms",    0644, d,
			   cmh_rng_timeout_drbg_ptr());
}

/* -- Public Interface ------------------------------------------------------ */

/**
 * cmh_debugfs_init() - Create debugfs directory hierarchy for CMH
 * @cfg: Platform configuration containing mailbox count and register bases.
 *
 * Allocates per-mailbox statistics and creates the /sys/kernel/debug/cmh/
 * tree with per-mailbox counters, fault-injection files, and transaction
 * manager statistics.  debugfs is optional; failure to create entries does
 * not prevent module initialisation.
 *
 * Return: 0 on success (always returns 0 -- debugfs is best-effort).
 */
int cmh_debugfs_init(struct cmh_config *cfg)
{
	u32 mbx_count = cfg->mbx_count;
	u32 i;

	dbgfs.root = debugfs_create_dir("cmh", NULL);
	if (IS_ERR_OR_NULL(dbgfs.root)) {
		if (!IS_ERR(dbgfs.root))
			dev_warn(cmh_dev(), "debugfs: creation returned NULL -- counters disabled\n");
		else
			dev_warn(cmh_dev(), "debugfs: creation failed (rc=%ld) -- counters disabled\n",
				 PTR_ERR(dbgfs.root));
		dbgfs.root = NULL;
		return 0;  /* debugfs is optional -- never fail module init */
	}

	dbgfs.mbx_count = mbx_count;
	dbgfs.cfg = cfg;
	dbgfs.mbx = kcalloc(mbx_count, sizeof(*dbgfs.mbx), GFP_KERNEL);
	if (!dbgfs.mbx) {
		debugfs_remove_recursive(dbgfs.root);
		dbgfs.root = NULL;
		return 0;
	}

	for (i = 0; i < mbx_count; i++)
		create_mbx_dir(i, dbgfs.root);

	create_tm_dir(dbgfs.root);

	create_config_dir(dbgfs.root);

	dev_dbg(cmh_dev(), "debugfs: initialized (%u mailboxes)\n", mbx_count);
	return 0;
}

/**
 * cmh_debugfs_cleanup() - Remove all CMH debugfs entries
 *
 * Tears down the /sys/kernel/debug/cmh/ tree and frees per-mailbox
 * statistics memory.  Safe to call even if cmh_debugfs_init() was never
 * called or failed.
 */
void cmh_debugfs_cleanup(void)
{
	debugfs_remove_recursive(dbgfs.root);
	dbgfs.root = NULL;
	kfree(dbgfs.mbx);
	dbgfs.mbx = NULL;
	dev_dbg(cmh_dev(), "debugfs: cleaned up\n");
}

/**
 * cmh_debugfs_mbx_stats() - Return per-mailbox statistics pointer
 * @mbx_idx: Zero-based mailbox index.
 *
 * Return: Pointer to the statistics structure for @mbx_idx, or NULL if
 *         debugfs is disabled or @mbx_idx is out of range.
 */
struct cmh_mbx_stats *cmh_debugfs_mbx_stats(u32 mbx_idx)
{
	if (!dbgfs.mbx || mbx_idx >= dbgfs.mbx_count)
		return NULL;
	return &dbgfs.mbx[mbx_idx];
}

/**
 * cmh_debugfs_tm_stats() - Return transaction manager statistics pointer
 *
 * Return: Pointer to the singleton TM statistics structure.  The pointer
 *         is always valid (points to static storage).
 */
struct cmh_tm_stats *cmh_debugfs_tm_stats(void)
{
	return &dbgfs.tm;
}
