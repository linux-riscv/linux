/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- AES Crypto API Drivers
 *
 * Registers AES algorithms with the Linux crypto subsystem:
 *   skcipher: ecb/cbc/ctr/cfb/xts(aes)
 *   aead:     gcm/ccm(aes)
 *   shash:    cmac(aes)
 */

#ifndef CMH_AES_H
#define CMH_AES_H

int  cmh_aes_register(void);
void cmh_aes_unregister(void);

int  cmh_aes_aead_register(void);
void cmh_aes_aead_unregister(void);

int  cmh_aes_cmac_register(void);
void cmh_aes_cmac_unregister(void);

#endif /* CMH_AES_H */
