/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API HMAC Driver
 *
 * Registers HMAC ahash algorithms (HMAC-SHA-2, HMAC-SHA-3) with the
 * Linux crypto subsystem using HC_CMD_HMAC.
 */

#ifndef CMH_HMAC_H
#define CMH_HMAC_H

int  cmh_hmac_register(void);
void cmh_hmac_unregister(void);

#endif /* CMH_HMAC_H */
