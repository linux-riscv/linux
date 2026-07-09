/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API KMAC Driver
 *
 * Registers KMAC-128 and KMAC-256 ahash algorithms using
 * HC_CMD_KMAC with inline customization string S.
 */

#ifndef CMH_KMAC_H
#define CMH_KMAC_H

int  cmh_kmac_register(void);
void cmh_kmac_unregister(void);

#endif /* CMH_KMAC_H */
