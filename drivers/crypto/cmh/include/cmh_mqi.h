/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Mailbox Queue Initializer
 *
 * Allocates DMA-capable queue buffers and programs MBX registers
 * via the MBX lock/setup/enable/unlock register sequence.
 */

#ifndef CMH_MQI_H
#define CMH_MQI_H

#include "cmh_config.h"

#define MBX_LOCK_TIMEOUT_MS     1000
#define MBX_LOCK_POLL_MIN_US    10
#define MBX_LOCK_POLL_MAX_US    50
#define MBX_HOST_INFO_LKM       0x4C4B4D00U  /* "LKM\0" as host identifier */

/**
 * cmh_mqi_init() - Allocate MBX queue buffers and program registers
 * @cfg: Global device configuration
 *
 * Performs the lock/setup/enable/unlock sequence for each configured MBX.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mqi_init(struct cmh_config *cfg);

/**
 * cmh_mqi_cleanup() - Free MBX queue buffers and release locks
 * @cfg: Global device configuration
 */
void cmh_mqi_cleanup(struct cmh_config *cfg);

#endif /* CMH_MQI_H */
