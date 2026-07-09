/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH -- Key Management misc_device (/dev/cmh_mgmt)
 *
 * ioctl interface for key CRUD + datastore export/import,
 * PKE operations (RSA, ECDSA, ECDH, EdDSA),
 * and PQC operations (ML-KEM, ML-DSA, SLH-DSA).
 *
 * Registered alongside crypto algorithms in module_init,
 * unregistered before them in module_exit.
 */

#ifndef CMH_MGMT_H
#define CMH_MGMT_H

#ifdef CONFIG_CRYPTO_DEV_CMH_MGMT

/*
 * Pin all mgmt ioctls to MBX 0 for DS ownership and SYS_REF_TEMP scope.
 * Shared by cmh_mgmt.c, cmh_mgmt_pke.c, cmh_mgmt_pqc.c, cmh_pke_sm2.c.
 */
#define MGMT_MBX	0

/* Maximum DMA buffer size for key data / datastore blobs */
#define CMH_MGMT_MAX_DATA_LEN	(256 * 1024)  /* 256 KB */

int  cmh_mgmt_register(void);
void cmh_mgmt_unregister(void);

/* -- PKE ioctl handlers (cmh_mgmt_pke.c) -- */
int cmh_mgmt_pke_rsa_enc(void __user *argp);
int cmh_mgmt_pke_rsa_dec(void __user *argp);
int cmh_mgmt_pke_rsa_crt_dec(void __user *argp);
int cmh_mgmt_pke_rsa_keygen(void __user *argp);
int cmh_mgmt_pke_ecdsa_sign(void __user *argp);
int cmh_mgmt_pke_ecdh(void __user *argp);
int cmh_mgmt_pke_ecdh_keygen(void __user *argp);
int cmh_mgmt_pke_eddsa_sign(void __user *argp);
int cmh_mgmt_pke_eddsa_verify(void __user *argp);
int cmh_mgmt_pke_ec_keygen(void __user *argp);
int cmh_mgmt_pke_ec_pubgen(void __user *argp);
int cmh_mgmt_pke_eddsa_keygen_sca(void __user *argp);

/* -- PQC ioctl handlers (cmh_mgmt_pqc.c) -- */
int cmh_mgmt_ml_kem_keygen(void __user *argp);
int cmh_mgmt_ml_kem_enc(void __user *argp);
int cmh_mgmt_ml_kem_dec(void __user *argp);
int cmh_mgmt_ml_dsa_keygen(void __user *argp);
int cmh_mgmt_ml_dsa_sign(void __user *argp);
int cmh_mgmt_slhdsa_keygen(void __user *argp);
int cmh_mgmt_slhdsa_sign(void __user *argp);
int cmh_mgmt_slhdsa_sign_prehash(void __user *argp);

#else /* !CONFIG_CRYPTO_DEV_CMH_MGMT */

static inline int  cmh_mgmt_register(void) { return 0; }
static inline void cmh_mgmt_unregister(void) { }

#endif /* CONFIG_CRYPTO_DEV_CMH_MGMT */

#endif /* CMH_MGMT_H */
