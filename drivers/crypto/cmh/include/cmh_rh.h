/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Response Handler
 *
 * IRQ-driven completion processing.  Uses request_threaded_irq():
 *   - Hardirq: read+clear MBX interrupt registers, wake thread
 *   - Threaded handler: walk per-MBX transaction queues,
 *     fire completion callbacks, free transaction objects
 *
 * The Response Handler consumes transaction_obj entries enqueued
 * by the Transaction Manager (cmh_txn.c) on each per-mailbox txq.
 */

#ifndef CMH_RH_H
#define CMH_RH_H

#include "cmh_config.h"

/**
 * cmh_rh_init() - Register IRQ handler and start response processing
 * @cfg: Global device configuration
 *
 * Return: 0 on success, negative errno on failure.
 */
int  cmh_rh_init(struct cmh_config *cfg);

/**
 * cmh_rh_cleanup() - Free IRQ and stop response processing
 * @cfg: Global device configuration
 */
void cmh_rh_cleanup(struct cmh_config *cfg);

/**
 * cmh_rh_suspend() - Quiesce RH for system suspend
 * @cfg: Global device configuration
 *
 * Cancels the watchdog timer and masks MBX interrupts at the hardware
 * level.  IRQ handlers remain registered (standard PM pattern).
 * The threaded IRQ handler stays active so that cmh_tm_quiesce()
 * (called after this) can still drain in-flight transactions via
 * IRQ-driven completions.
 */
void cmh_rh_suspend(struct cmh_config *cfg);

/**
 * cmh_rh_resume() - Restart RH after system resume
 * @cfg: Global device configuration
 *
 * Re-synchronises per-MBX head tracking with hardware, clears stale
 * interrupt bits, re-enables MBX interrupt masks, and re-arms the
 * watchdog timer.  Must be called before cmh_tm_resume().
 */
void cmh_rh_resume(struct cmh_config *cfg);

/* debugfs timeout accessor (debug builds only) */
#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
unsigned int *cmh_rh_timeout_watchdog_ptr(void);
#endif

/**
 * cmh_rh_force_drain_mbx() - FLUSH + drain all pending transactions on a MBX
 * @mbx_idx: Mailbox index to drain
 *
 * Issues MBX_COMMAND_FLUSH, drains all pending transactions with
 * -ECANCELED, and resets all recovery bookkeeping (including the
 * wedged flag).  Safe to call at any time; acquires rh_process_lock.
 * Intended for debugfs last-resort recovery.
 */
void cmh_rh_force_drain_mbx(u32 mbx_idx);

/**
 * cmh_rh_mbx_is_wedged() - Check if a mailbox is permanently wedged
 * @mbx_idx: Mailbox index to check
 *
 * Returns true if the mailbox has failed RESTART+FLUSH recovery and
 * is offline.  Used by the TM to avoid submitting new work to a dead
 * mailbox.
 *
 * Return: true if wedged, false otherwise (including out-of-range idx).
 */
bool cmh_rh_mbx_is_wedged(u32 mbx_idx);

/**
 * cmh_rh_abort_mbx() - Issue MBX_COMMAND_ABORT under rh_process_lock
 * @mbx_idx: Mailbox index to abort
 *
 * Serialises the ABORT write with RESTART/FLUSH commands issued by the
 * watchdog, preventing command-register clobber races.
 */
void cmh_rh_abort_mbx(u32 mbx_idx);

#endif /* CMH_RH_H */
