/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- CCP Crypto API Drivers
 *
 * Registers CCP algorithms with the Linux crypto subsystem:
 *   skcipher: chacha20
 *   shash:    poly1305
 *   aead:     rfc7539(chacha20poly1305)
 */

#ifndef CMH_CCP_H
#define CMH_CCP_H

int  cmh_ccp_register(void);
void cmh_ccp_unregister(void);

int  cmh_ccp_aead_register(void);
void cmh_ccp_aead_unregister(void);

int  cmh_ccp_poly_register(void);
void cmh_ccp_poly_unregister(void);

#endif /* CMH_CCP_H */
