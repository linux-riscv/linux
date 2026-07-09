/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- debugfs Per-MBX and TM Counters
 *
 * Exposes diagnostic counters under /sys/kernel/debug/cmh/:
 *
 *   mbxN/vcqs_submitted      Total VCQs sent to MBX N
 *   mbxN/vcqs_completed      Total completions received
 *   mbxN/vcqs_errors         Total error completions
 *   mbxN/queue_full_count    Times select_mailbox() skipped this MBX
 *   mbxN/max_queue_depth     High-water mark of in-flight transactions
 *
 *   tm/cmq_posts             Total cmh_tm_post_command() calls
 *   tm/cmq_depth_max         High-water mark of CMQ length
 *   tm/cmq_eagain_count      Times CMQ was full (-EAGAIN)
 *   tm/backoff_count         Times TM backed off (all MBX queues full)
 *   tm/async_timeout_count   Async requests that timed out
 *
 * Counters are atomic64_t -- safe to read from any context.
 * When CONFIG_CRYPTO_DEV_CMH_DEBUG is off, all functions become no-ops and the
 * compiler eliminates the counter code entirely.
 */

#ifndef CMH_DEBUGFS_H
#define CMH_DEBUGFS_H

#include <linux/types.h>
#include <linux/atomic.h>

/* Per-Mailbox Statistics */

struct cmh_mbx_stats {
	atomic64_t vcqs_submitted;
	atomic64_t vcqs_completed;
	atomic64_t vcqs_errors;
	atomic64_t queue_full_count;
	atomic64_t max_queue_depth;
};

/* TM-Level Statistics */

struct cmh_tm_stats {
	atomic64_t cmq_posts;
	atomic64_t cmq_depth_max;
	atomic64_t cmq_eagain_count;
	atomic64_t backoff_count;
	atomic64_t async_timeout_count;
};

/**
 * cmh_stat_update_max() - Atomically update a high-water mark counter
 * @counter: atomic64_t counter to update
 * @val: New candidate value
 *
 * Updates @counter to @val if @val exceeds the current maximum.
 * Lock-free via atomic cmpxchg loop.
 */
static inline void cmh_stat_update_max(atomic64_t *counter, s64 val)
{
	s64 cur;

	do {
		cur = atomic64_read(counter);
		if (val <= cur)
			return;
	} while (atomic64_cmpxchg(counter, cur, val) != cur);
}

/* Interface (stub when CONFIG_CRYPTO_DEV_CMH_DEBUG is off) */

struct cmh_config;

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG

int  cmh_debugfs_init(struct cmh_config *cfg);
void cmh_debugfs_cleanup(void);

struct cmh_mbx_stats *cmh_debugfs_mbx_stats(u32 mbx_idx);
struct cmh_tm_stats  *cmh_debugfs_tm_stats(void);

#else /* !CONFIG_CRYPTO_DEV_CMH_DEBUG */

static inline int  cmh_debugfs_init(struct cmh_config *c) { return 0; }
static inline void cmh_debugfs_cleanup(void) {}
static inline struct cmh_mbx_stats *cmh_debugfs_mbx_stats(u32 i) { return NULL; }
static inline struct cmh_tm_stats  *cmh_debugfs_tm_stats(void)   { return NULL; }

#endif /* CONFIG_CRYPTO_DEV_CMH_DEBUG */
#endif /* CMH_DEBUGFS_H */
