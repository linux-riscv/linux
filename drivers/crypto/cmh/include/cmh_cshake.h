/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API CSHAKE Driver
 *
 * Registers cSHAKE-128 and cSHAKE-256 ahash algorithms using
 * HC_CMD_CSHAKE with inline customization string S.
 */

#ifndef CMH_CSHAKE_H
#define CMH_CSHAKE_H

int  cmh_cshake_register(void);
void cmh_cshake_unregister(void);

#endif /* CMH_CSHAKE_H */
