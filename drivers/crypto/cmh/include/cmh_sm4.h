/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM4 Crypto API Drivers
 *
 * Registers SM4 algorithms with the Linux crypto subsystem:
 *   skcipher: ecb/cbc/ctr/cfb/xts(sm4)
 *   aead:     gcm/ccm(sm4)
 *   shash:    cmac/xcbc(sm4)
 */

#ifndef CMH_SM4_H
#define CMH_SM4_H

int  cmh_sm4_register(void);
void cmh_sm4_unregister(void);

int  cmh_sm4_aead_register(void);
void cmh_sm4_aead_unregister(void);

int  cmh_sm4_cmac_register(void);
void cmh_sm4_cmac_unregister(void);

#endif /* CMH_SM4_H */
