/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM2 PKE Ioctl Handler Declarations
 *
 * SM2 signature (GM/T 0003.2) requires the caller to compute
 * ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 * and pass SM3(ZA || M) as the digest to the sign/verify path.
 * The CMH eSW does NOT compute ZA internally; the full
 * identity pre-hash is the caller's responsibility.
 *
 * For the in-kernel akcipher "sm2" algorithm this means the
 * caller (e.g. asymmetric_key subsystem) must pre-hash with ZA
 * before invoking verify.  The SM2_ID_DIGEST ioctl below can
 * compute ZA for userspace callers of the misc-device path.
 */

#ifndef CMH_PKE_SM2_H
#define CMH_PKE_SM2_H

int cmh_mgmt_sm2_ecdh_keygen(void __user *argp);
int cmh_mgmt_sm2_ecdh(void __user *argp);
int cmh_mgmt_sm2_dec_point(void __user *argp);
int cmh_mgmt_sm2_enc_point(void __user *argp);
int cmh_mgmt_sm2_id_digest(void __user *argp);
int cmh_mgmt_sm2_ecdh_hash(void __user *argp);
int cmh_mgmt_sm2_dec_hash(void __user *argp);
int cmh_mgmt_sm2_enc_hash(void __user *argp);

#endif /* CMH_PKE_SM2_H */
