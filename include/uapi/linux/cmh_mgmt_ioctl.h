/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Key Management ioctl Interface (User-Space API)
 *
 * ioctl commands for /dev/cmh_mgmt -- key CRUD, datastore
 * export/import, KIC key derivation, PKE, SM2, and PQC operations.
 *
 * Relationship to the in-kernel crypto API
 * -----------------------------------------
 * Most commands here have no crypto API representation (no transform
 * type or verb exists): keystore CRUD, key generation, KIC key
 * derivation, ML-KEM encapsulate/decapsulate, SM2 multi-step
 * encrypt/decrypt/key-exchange, EdDSA, EAC, and DRBG configuration.
 * For these the character device is the only available UAPI.
 *
 * A bounded subset names primitives the driver ALSO registers with
 * the crypto API, and the overlap is intentional:
 *   - Hardware-held-key operations (RSA decrypt, ECDSA/ML-DSA/SLH-DSA
 *     sign, ECDH) reference a private key by datastore handle.  The
 *     crypto API set_priv_key()/set_secret() take only raw key bytes
 *     and cannot name a key that never leaves the hardware; these
 *     ioctls keep the key hardware-resident.  The registered
 *     transforms serve raw-key in-kernel users -- the paths are
 *     complementary.
 *
 * Multi-step protocol flows are documented above the PKE and SM2
 * struct sections.  Single-command ioctls are self-documenting.
 *
 * Versioned structs: user space sets .version = CMH_MGMT_V1 so the
 * driver can extend structs in the future without breaking ABI.
 */

#ifndef _UAPI_CMH_MGMT_IOCTL_H
#define _UAPI_CMH_MGMT_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/const.h>

#define CMH_MGMT_V1		1

/* Special reference values */
#define CMH_REF_NONE		0x0000000000000000ULL	/* no key (plaintext) */

/* Flags for cmh_ioctl_key_new.flags / cmh_ioctl_key_write.flags */
#define CMH_FLAG_PT		_BITUL(16)	/* key can be read as plaintext */
#define CMH_FLAG_XC		_BITUL(17)	/* key can be exported over XC bus */
#define CMH_FLAG_SCA		_BITUL(18)	/* SCA key stored in 2 shares */
#define CMH_FLAG_MASK		(CMH_FLAG_PT | CMH_FLAG_XC | CMH_FLAG_SCA)

/*
 * Datastore key types -- the LKM maps these to core IDs internally.
 * User space passes these in cmh_ioctl_key_new.ds_type.
 */
#define CMH_DS_RAW_VALUE		1
#define CMH_DS_AES_KEY			2
#define CMH_DS_AES_XTS_KEY		3
#define CMH_DS_HMAC_KEY			4
#define CMH_DS_KMAC_KEY			5
#define CMH_DS_SM4_KEY			6
#define CMH_DS_CHACHA20_KEY		7

/* PKE key types -- all map to CORE_ID_PKE (0x0A) */
#define CMH_DS_RSA_PRIV_KEY		10
#define CMH_DS_RSA_PUB_KEY		11
#define CMH_DS_RSA_CRT_KEY		12
#define CMH_DS_ECDSA_PRIV_KEY		13
#define CMH_DS_ECDSA_PUB_KEY		14
#define CMH_DS_ECDH_PRIV_KEY		15
#define CMH_DS_EDDSA_PRIV_KEY		16
#define CMH_DS_SHARED_SECRET		17
#define CMH_DS_SM2_PRIV_KEY		18

/* QSE key types -- map to CORE_ID_QSE (0x09) */
#define CMH_DS_ML_KEM_DK		20
#define CMH_DS_ML_DSA_SK		21

/* HCQ key types -- map to CORE_ID_HCQ (0x08) */
#define CMH_DS_SLHDSA_SK		25

/* ioctl argument structures */

struct cmh_ioctl_key_new {
	__u32 version;		/* must be CMH_MGMT_V1 */
	__u32 ds_type;		/* CMH_DS_* key type */
	__u32 len;		/* key length in bytes */
	__u32 flags;		/* CMH_FLAG_* (e.g. CMH_FLAG_PT) */
	__u64 cid;		/* caller ID (name) for the key */
	__u64 ref;		/* [out] CMH eSW returns key_ref here */
};

struct cmh_ioctl_key_write {
	__u32 version;
	__u32 len;		/* key data length */
	__u32 ds_type;		/* CMH_DS_* key type */
	__u32 flags;		/* CMH_FLAG_* (e.g. CMH_FLAG_PT) */
	__u64 ref;		/* key reference from KEY_NEW */
	__u64 wrap_key;		/* wrapping key ref (CMH_REF_NONE = plaintext) */
	__u64 data;		/* user-space pointer to key material */
};

struct cmh_ioctl_key_read {
	__u32 version;
	__u32 len;		/* buffer length */
	__u64 ref;		/* key reference */
	__u64 wrap_key;		/* wrapping key ref (CMH_REF_NONE = plaintext) */
	__u64 data;		/* user-space pointer to output buffer */
	__u32 out_len;		/* [out] actual bytes written */
	__u32 __reserved;
};

struct cmh_ioctl_key_find {
	__u32 version;
	__u32 __reserved;
	__u64 cid;		/* caller ID to search for */
	__u64 ref;		/* [out] resolved key reference */
	__u32 len;		/* [out] key length */
	__u32 type;		/* [out] key type */
};

/*
 * KEY_LIST -- iterate datastore objects.
 *
 * Pass start_ref=0 to begin from the first accessible object.
 * On return, ref/cid/len/type describe that object.  Pass the
 * returned ref as start_ref in the next call to advance.  Iteration
 * ends when ref == 0 (no more objects).
 */
struct cmh_ioctl_key_list {
	__u32 version;
	__u32 __reserved;
	__u64 start_ref;	/* starting DS reference (0 = first) */
	__u64 ref;		/* [out] object reference */
	__u64 cid;		/* [out] caller ID */
	__u32 len;		/* [out] object length */
	__u32 type;		/* [out] object type */
};

struct cmh_ioctl_key_grant {
	__u32 version;
	__u32 __reserved;
	__u64 ref;		/* key reference */
	__u64 read;		/* per-MBX read permission bitfield */
	__u64 write;		/* per-MBX write permission bitfield */
	__u64 execute;		/* per-MBX execute permission bitfield */
};

/* Export blob overhead beyond the raw object data (bytes) */
#define CMH_DS_EXPORT_OVERHEAD_WRAPPED	48	/* 16B hdr + 16B nonce + 16B tag */
#define CMH_DS_EXPORT_OVERHEAD_PLAIN	16	/* 16B hdr only */

/**
 * struct cmh_ioctl_ds_export - Export a datastore object to a wrapped blob
 * @version:   protocol version (CMH_MGMT_V1)
 * @len:       DMA buffer size; must be >= export blob size:
 *               wrapped:   CMH_DS_EXPORT_OVERHEAD_WRAPPED + object_len
 *               plaintext: CMH_DS_EXPORT_OVERHEAD_PLAIN + object_len
 *             object_len is known from KEY_NEW or KEY_FIND.
 *             If too small, the eSW rejects the command (-EIO).
 * @cid:       caller ID of the object to export
 * @wrap_key:  wrapping key ref (CMH_REF_NONE = plaintext export)
 * @data:      user-space pointer to output buffer (at least @len bytes)
 * @out_len:   [out] actual blob bytes written on success
 * @__reserved: must be zero
 */
struct cmh_ioctl_ds_export {
	__u32 version;
	__u32 len;		/* buffer length (see sizing rule above) */
	__u64 cid;		/* caller ID for response tagging */
	__u64 wrap_key;		/* wrapping key ref (CMH_REF_NONE = plaintext) */
	__u64 data;		/* user-space pointer to output buffer */
	__u32 out_len;		/* [out] actual bytes written */
	__u32 __reserved;
};

struct cmh_ioctl_ds_import {
	__u32 version;
	__u32 len;		/* blob length */
	__u64 wrap_key;		/* wrapping key ref (CMH_REF_NONE = plaintext) */
	__u64 data;		/* user-space pointer to import blob */
};

/* Flags for cmh_ioctl_kic_hkdf1.flags / cmh_ioctl_kic_hkdf2.flags */
#define CMH_KIC_FLAG_TEMP	0x01	/* store result in TEMP (not persistent DS) */

/*
 * KIC hardware base key references.
 *
 * Each CMH device has up to 8 hardware base keys provisioned in OTP/fuses.
 * These values are passed in the base_key field of KIC ioctl structs.
 * The key valid bitmask is visible via R_KIC_KEY_VALID (MMIO 0x100).
 */
#define CMH_KIC_KEY1		0x0000000100000001ULL
#define CMH_KIC_KEY2		0x0000000200000002ULL
#define CMH_KIC_KEY3		0x0000000300000003ULL
#define CMH_KIC_KEY4		0x0000000400000004ULL
#define CMH_KIC_KEY5		0x0000000500000005ULL
#define CMH_KIC_KEY6		0x0000000600000006ULL
#define CMH_KIC_KEY7		0x0000000700000007ULL
#define CMH_KIC_KEY8		0x0000000800000008ULL

struct cmh_ioctl_kic_hkdf1 {
	__u32 version;
	__u32 key_len;		/* output key length (e.g., 32) */
	__u64 base_key;		/* KIC base key reference */
	__u64 cid;		/* CID for the new DS entry (ignored if TEMP) */
	__u64 label;		/* user-space pointer to label data */
	__u32 label_len;	/* label length in bytes */
	__u32 flags;		/* CMH_KIC_FLAG_* */
	__u64 ref;		/* [out] derived key reference */
};

struct cmh_ioctl_kic_hkdf2 {
	__u32 version;
	__u32 key_len;		/* output key length (e.g., 32) */
	__u64 base_key;		/* KIC base key reference */
	__u64 salt_key;		/* salt key reference (CMH_REF_NONE = no salt) */
	__u64 cid;		/* CID for the new DS entry (ignored if TEMP) */
	__u64 label;		/* user-space pointer to label data */
	__u32 label_len;	/* label length in bytes */
	__u32 flags;		/* CMH_KIC_FLAG_* */
	__u64 ref;		/* [out] derived key reference */
};

struct cmh_ioctl_kic_aes_cmac_kdf {
	__u32 version;
	__u32 key_len;		/* base & output key length (must be 32) */
	__u64 base_key;		/* KIC base key or DS reference */
	__u64 cid;		/* CID for the new DS entry (ignored if TEMP) */
	__u64 label;		/* user-space pointer to label data */
	__u32 label_len;	/* label length in bytes */
	__u32 flags;		/* CMH_KIC_FLAG_* */
	__u64 ref;		/* [out] derived key reference */
};

#define KIC_DKEK_MAX_METADATA	64	/* max metadata length for DKEK */

struct cmh_ioctl_kic_dkek_derive {
	__u32 version;
	__u32 host_id;		/* target host ID (0 = caller's own) */
	__u64 base_key;		/* KIC base key reference */
	__u64 cid;		/* CID for the new DS entry (ignored if TEMP) */
	__u64 metadata;		/* user-space pointer to metadata */
	__u32 metadata_len;	/* metadata length in bytes */
	__u32 flags;		/* CMH_KIC_FLAG_* */
	__u64 ref;		/* [out] derived KEK reference */
};

/* -- PKE ioctl argument structures ----------- */

/*
 * PKE multi-step protocol flows
 *
 * RSA encrypt/decrypt:
 *   1. KEY_NEW(CMH_DS_RSA_PRIV_KEY) + KEY_WRITE -> priv_ref (or RSA_KEYGEN -> priv_ref)
 *   2. RSA_ENC(e, n, plaintext) -> ciphertext         (public key = raw e,n)
 *   3. RSA_DEC(e, n, ciphertext, priv_ref) -> plaintext   (or RSA_CRT_DEC)
 *
 * ECDSA sign:
 *   1. EC_KEYGEN(curve) -> priv_ref                    (or KEY_NEW + KEY_WRITE)
 *   2. EC_PUBGEN(priv_ref) -> public_key               (raw x||y returned)
 *   3. ECDSA_SIGN(digest, priv_ref) -> signature
 *   SM2 sign uses the same path with curve=CMH_CURVE_SM2.
 *
 * ECDH shared secret:
 *   1. EC_KEYGEN(curve) -> priv_ref                    (or KEY_NEW + KEY_WRITE)
 *   2. ECDH_KEYGEN(priv_ref) -> public_key_x           (derive pub from priv)
 *   3. Exchange public keys with peer
 *   4. ECDH(peer_key_x, priv_ref) -> shared_secret     (raw or DS ref via FLAG_DS_RESULT)
 *
 * EdDSA sign/verify:
 *   1. EC_KEYGEN(CURVE_25519 or CURVE_448) -> priv_ref
 *   2. EC_PUBGEN(priv_ref) -> public_key
 *   3. EDDSA_SIGN(message, priv_ref) -> signature      (pure EdDSA, not prehash)
 *   4. EDDSA_VERIFY(message, signature, public_key_y)
 *   For Ed448 SCA: EDDSA_KEYGEN_SCA(priv_ref) -> sca_ref (2-share blinded key)
 *
 * SM2 encryption (GM/T 0003.4):
 *   1. EC_KEYGEN(CMH_CURVE_SM2) -> priv_ref            (or KEY_NEW + KEY_WRITE)
 *   2. EC_PUBGEN(priv_ref) -> public_key
 *   3. SM2_ENC_POINT(public_key) -> C1, enc_point      (nonce_len=0: HW ephemeral)
 *   4. SM2_ENC_HASH(enc_point, message) -> ciphertext   (C1||C3||C2)
 *   Decrypt:
 *   5. SM2_DEC_POINT(C1, priv_ref) -> dec_point
 *   6. SM2_DEC_HASH(ciphertext, dec_point) -> plaintext
 *   enc_point and dec_point are raw DMA buffers (64B each), not DS refs.
 *
 * SM2 key exchange (GM/T 0003.3):
 *   1. EC_KEYGEN(CMH_CURVE_SM2) -> priv_ref            (long-lived, persistent DS)
 *   2. EC_PUBGEN(priv_ref) -> public_key
 *   3. SM2_ID_DIGEST(id, public_key) -> ZA             (SM3-based identity digest)
 *   4. SM2_ECDH_KEYGEN(nonce) -> session_key, r        (ephemeral scalar r)
 *      - nonce_len=32: caller supplies r (deterministic)
 *      - nonce_len=0:  HW generates r, writes it back to .nonce
 *      Exchange session_key with peer.
 *   5. SM2_ECDH(r, priv_ref, peer_pub, peer_sess) -> shared_point
 *      - Must pass the same r from step 4 (nonce_len=32)
 *      - shared_point_ref=0: reads back raw shared_point, destroys DS slot
 *      - shared_point_ref=&ref: keeps DS slot alive, writes ref for ECDH_HASH
 *   6. SM2_ECDH_HASH(shared_point_ref, ZA_self, ZA_peer) -> shared_key (16B)
 *      - shared_point_ref is a persistent DS reference from step 5
 *      - The DS slot is consumed by the hub; caller should delete it afterward
 *   The nonce r is a raw 32-byte scalar in userspace memory between steps 4-5.
 *   The shared_point is a persistent DS ref between steps 5-6.
 *   The long-lived private key (priv_ref) persists independently.
 */

/* PKE operation flags */
#define CMH_PKE_FLAG_DS_RESULT	_BITUL(0)	/* store result in DS, return ref */

struct cmh_ioctl_pke_rsa_enc {
	__u32 version;
	__u32 bits;		/* RSA key size in bits (512-4096) */
	__u64 e;		/* user-space pointer to public exponent */
	__u32 e_len;		/* exponent length in bytes */
	__u32 __reserved;
	__u64 n;		/* user-space pointer to modulus */
	__u64 input;		/* user-space pointer to input data */
	__u64 output;		/* user-space pointer to output buffer */
};

struct cmh_ioctl_pke_rsa_dec {
	__u32 version;
	__u32 bits;
	__u64 e;		/* public exponent */
	__u32 e_len;
	__u32 __reserved;
	__u64 n;		/* modulus */
	__u64 input;		/* ciphertext */
	__u64 output;		/* plaintext output */
	__u64 key_ref;		/* private key DS reference */
};

struct cmh_ioctl_pke_rsa_crt_dec {
	__u32 version;
	__u32 bits;
	__u64 e;
	__u32 e_len;
	__u32 __reserved;
	__u64 n;
	__u64 input;
	__u64 output;
	__u64 crt_ref;		/* CRT key DS reference */
};

struct cmh_ioctl_pke_rsa_keygen {
	__u32 version;
	__u32 bits;		/* key size in bits */
	__u64 e;		/* user-space pointer to public exponent */
	__u32 e_len;
	__u32 flags;		/* CMH_FLAG_* */
	__u64 n;		/* [out] user-space pointer to modulus buffer */
	__u64 d_cid;		/* CID for private key DS entry */
	__u64 d_ref;		/* [out] private key reference */
	__u64 crt_cid;		/* CID for CRT key DS entry (0 = skip CRT) */
	__u64 crt_ref;		/* [out] CRT key reference */
};

struct cmh_ioctl_pke_ecdsa_sign {
	__u32 version;
	__u32 curve;		/* ABI curve ID (e.g. 0x03 = P-256) */
	__u64 digest;		/* user-space pointer to hash digest */
	__u32 digest_len;	/* digest length in bytes */
	__u32 __reserved;
	__u64 signature;	/* [out] user-space pointer to (r,s) */
	__u64 key_ref;		/* private key DS reference */
};

struct cmh_ioctl_pke_ecdh {
	__u32 version;
	__u32 curve;
	__u64 peer_key_x;	/* user-space pointer to peer public key X */
	__u64 key_ref;		/* private key DS reference */
	__u32 flags;		/* CMH_PKE_FLAG_DS_RESULT */
	__u32 __reserved;
	__u64 result_cid;	/* CID for DS result (if FLAG_DS_RESULT) */
	__u64 output;		/* [out] raw shared secret or DS ref */
};

struct cmh_ioctl_pke_ecdh_keygen {
	__u32 version;
	__u32 curve;
	__u64 key_ref;		/* private key DS reference */
	__u64 public_key_x;	/* [out] user-space pointer to public key X */
};

struct cmh_ioctl_pke_eddsa_sign {
	__u32 version;
	__u32 curve;		/* CURVE_25519 or CURVE_448 */
	__u64 digest;		/* user-space ptr to message (not digest) */
	__u32 digest_len;
	__u32 __reserved;
	__u64 signature;	/* [out] user-space pointer to signature */
	__u64 key_ref;		/* private key DS reference */
};

struct cmh_ioctl_pke_eddsa_verify {
	__u32 version;
	__u32 curve;
	__u64 digest;
	__u32 digest_len;
	__u32 __reserved;
	__u64 signature;
	__u64 public_key_y;	/* user-space pointer to public key Y */
};

struct cmh_ioctl_pke_ec_keygen {
	__u32 version;
	__u32 curve;
	__u32 flags;		/* CMH_FLAG_* */
	__u32 __reserved;
	__u64 cid;		/* CID for the new key DS entry */
	__u64 ref;		/* [out] private key reference */
};

struct cmh_ioctl_pke_ec_pubgen {
	__u32 version;
	__u32 curve;
	__u64 key_ref;		/* private key DS reference */
	__u64 public_key;	/* [out] user-space pointer to public key */
};

struct cmh_ioctl_pke_eddsa_keygen_sca {
	__u32 version;
	__u32 curve;		/* must be CURVE_448 */
	__u64 key_ref;		/* input: normal Ed448 private key DS ref */
	__u64 cid;		/* CID for the new SCA key DS entry */
	__u64 sca_ref;		/* [out] SCA private key reference */
};

/*
 * ioctl numbers -- type 'J', sequential.
 * 'C' conflicts with OSS sound, CAPI/ISDN, and COSA WAN drivers;
 * 'J' is unregistered in Documentation/userspace-api/ioctl/ioctl-number.rst.
 */

#define CMH_MGMT_IOC_MAGIC	'J'

#define CMH_IOCTL_KEY_NEW	_IOWR(CMH_MGMT_IOC_MAGIC, 0x01, struct cmh_ioctl_key_new)
#define CMH_IOCTL_KEY_WRITE	_IOW(CMH_MGMT_IOC_MAGIC,  0x02, struct cmh_ioctl_key_write)
#define CMH_IOCTL_KEY_READ	_IOWR(CMH_MGMT_IOC_MAGIC, 0x03, struct cmh_ioctl_key_read)
#define CMH_IOCTL_KEY_FIND	_IOWR(CMH_MGMT_IOC_MAGIC, 0x04, struct cmh_ioctl_key_find)
#define CMH_IOCTL_KEY_GRANT	_IOW(CMH_MGMT_IOC_MAGIC,  0x05, struct cmh_ioctl_key_grant)
#define CMH_IOCTL_KEY_DELETE	_IOW(CMH_MGMT_IOC_MAGIC,  0x06, struct cmh_ioctl_key_grant)
#define CMH_IOCTL_DS_EXPORT	_IOWR(CMH_MGMT_IOC_MAGIC, 0x07, struct cmh_ioctl_ds_export)
#define CMH_IOCTL_DS_IMPORT	_IOW(CMH_MGMT_IOC_MAGIC,  0x08, struct cmh_ioctl_ds_import)
#define CMH_IOCTL_KIC_HKDF1	_IOWR(CMH_MGMT_IOC_MAGIC, 0x09, struct cmh_ioctl_kic_hkdf1)
#define CMH_IOCTL_KIC_HKDF2	_IOWR(CMH_MGMT_IOC_MAGIC, 0x0A, struct cmh_ioctl_kic_hkdf2)
#define CMH_IOCTL_KEY_NEW_RANDOM _IOWR(CMH_MGMT_IOC_MAGIC, 0x0B, struct cmh_ioctl_key_new)
#define CMH_IOCTL_KIC_AES_CMAC_KDF _IOWR(CMH_MGMT_IOC_MAGIC, 0x0C, \
					struct cmh_ioctl_kic_aes_cmac_kdf)
#define CMH_IOCTL_KIC_DKEK_DERIVE _IOWR(CMH_MGMT_IOC_MAGIC, 0x0D, \
					struct cmh_ioctl_kic_dkek_derive)
#define CMH_IOCTL_KEY_LIST	_IOWR(CMH_MGMT_IOC_MAGIC, 0x0E, struct cmh_ioctl_key_list)

/* PKE operation ioctls */
#define CMH_IOCTL_PKE_RSA_ENC		_IOWR(CMH_MGMT_IOC_MAGIC, 0x10, \
					struct cmh_ioctl_pke_rsa_enc)
#define CMH_IOCTL_PKE_RSA_DEC		_IOWR(CMH_MGMT_IOC_MAGIC, 0x11, \
					struct cmh_ioctl_pke_rsa_dec)
#define CMH_IOCTL_PKE_RSA_CRT_DEC	_IOWR(CMH_MGMT_IOC_MAGIC, 0x12, \
					struct cmh_ioctl_pke_rsa_crt_dec)
#define CMH_IOCTL_PKE_RSA_KEYGEN	_IOWR(CMH_MGMT_IOC_MAGIC, 0x13, \
					struct cmh_ioctl_pke_rsa_keygen)
#define CMH_IOCTL_PKE_ECDSA_SIGN	_IOWR(CMH_MGMT_IOC_MAGIC, 0x14, \
					struct cmh_ioctl_pke_ecdsa_sign)
#define CMH_IOCTL_PKE_ECDH		_IOWR(CMH_MGMT_IOC_MAGIC, 0x16, \
					struct cmh_ioctl_pke_ecdh)
#define CMH_IOCTL_PKE_ECDH_KEYGEN	_IOWR(CMH_MGMT_IOC_MAGIC, 0x17, \
					struct cmh_ioctl_pke_ecdh_keygen)
#define CMH_IOCTL_PKE_EDDSA_SIGN	_IOWR(CMH_MGMT_IOC_MAGIC, 0x18, \
					struct cmh_ioctl_pke_eddsa_sign)
#define CMH_IOCTL_PKE_EDDSA_VERIFY	_IOW(CMH_MGMT_IOC_MAGIC,  0x19, \
					struct cmh_ioctl_pke_eddsa_verify)
#define CMH_IOCTL_PKE_EC_KEYGEN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x1A, \
					struct cmh_ioctl_pke_ec_keygen)
#define CMH_IOCTL_PKE_EC_PUBGEN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x1B, \
					struct cmh_ioctl_pke_ec_pubgen)
#define CMH_IOCTL_PKE_EDDSA_KEYGEN_SCA	_IOWR(CMH_MGMT_IOC_MAGIC, 0x1C, \
					struct cmh_ioctl_pke_eddsa_keygen_sca)

/* -- PQC ioctl argument structures ----------- */

/*
 * PQC operation flags (bits [2:0]).
 * PQC keygen ioctls accept CMH_FLAG_PT in bits [18:16] to explicitly
 * set the DS key storage attribute when CMH_QSE_FLAG_DS_REF is set.
 * CMH_FLAG_SCA and CMH_FLAG_XC are rejected -- QSE SCA protection uses
 * polynomial masking (CMH_QSE_FLAG_MASKED), not 2-share storage,
 * and the eSW dec/sign paths hardcode SYS_TYPE_FLAG_PT.
 * If no CMH_FLAG_* bits are set, DS keys default to CMH_FLAG_PT.
 */
#define CMH_QSE_FLAG_MASKED	_BITUL(0)	/* use masked (SCA-resistant) HW commands */
#define CMH_QSE_FLAG_DS_REF	_BITUL(1)	/* store key output in DS, return ref */
#define CMH_QSE_FLAG_HW_RNG	_BITUL(2)	/* use HW RNG for seed/randomness */
#define CMH_QSE_FLAG_MASK	(_BITUL(0) | _BITUL(1) | _BITUL(2))

/* -- SYS wrap header size -------------------- */
/* sys_read prepends a 16-byte header even for plaintext reads */
#define CMH_SYS_WRAP_HDR_SIZE	16

/* -- Seed / randomness lengths --------------- */

#define CMH_QSE_SEED_LEN		32	/* ML-KEM/ML-DSA seed size */
#define CMH_QSE_SEED_LEN_MASKED		64	/* seed size for masked mode */

/* -- ML-DSA ExternalMu sentinel -------------- */
/* Pass this as mlen to use 64-byte pre-hashed mu instead of raw message */
#define CMH_ML_DSA_MLEN_EXTERNAL_MU	0xFFFFFFFFU

/* -- ML-KEM size macros ---------------------- */

#define CMH_ML_KEM_EK_SIZE(k)		(384U * (k) + 32U)
#define CMH_ML_KEM_DK_SIZE(k)		(768U * (k) + 96U)
/* CT sizes: k=2 -> 768, k=3 -> 1088, k=4 -> 1568 */
#define CMH_ML_KEM_CT_SIZE_512		768U
#define CMH_ML_KEM_CT_SIZE_768		1088U
#define CMH_ML_KEM_CT_SIZE_1024		1568U
#define CMH_ML_KEM_SS_LEN		32U

/* -- ML-DSA size macros ---------------------- */
/* Indexed by mode: [0]=44 (mode=2), [1]=65 (mode=3), [2]=87 (mode=5) */

#define CMH_ML_DSA_44_PK_SIZE		1312U
#define CMH_ML_DSA_44_SK_SIZE		2560U
#define CMH_ML_DSA_44_SIG_SIZE		2420U
#define CMH_ML_DSA_65_PK_SIZE		1952U
#define CMH_ML_DSA_65_SK_SIZE		4032U
#define CMH_ML_DSA_65_SIG_SIZE		3309U
#define CMH_ML_DSA_87_PK_SIZE		2592U
#define CMH_ML_DSA_87_SK_SIZE		4896U
#define CMH_ML_DSA_87_SIG_SIZE		4627U

/* -- SLH-DSA parameter set IDs --------------- */

#define CMH_SLHDSA_SHAKE_128S		1U
#define CMH_SLHDSA_SHAKE_128F		2U
#define CMH_SLHDSA_SHAKE_192S		3U
#define CMH_SLHDSA_SHAKE_192F		4U
#define CMH_SLHDSA_SHAKE_256S		5U
#define CMH_SLHDSA_SHAKE_256F		6U
#define CMH_SLHDSA_SHA2_128S		7U
#define CMH_SLHDSA_SHA2_128F		8U
#define CMH_SLHDSA_SHA2_192S		9U
#define CMH_SLHDSA_SHA2_192F		10U
#define CMH_SLHDSA_SHA2_256S		11U
#define CMH_SLHDSA_SHA2_256F		12U
#define CMH_SLHDSA_PARAM_MAX		12U

/* SLH-DSA prehash algorithm IDs */
#define CMH_SLHDSA_PREHASH_SHA256	1U
#define CMH_SLHDSA_PREHASH_SHA512	2U
#define CMH_SLHDSA_PREHASH_SHAKE128	3U
#define CMH_SLHDSA_PREHASH_SHAKE256	4U
#define CMH_SLHDSA_PREHASH_MAX		4U

/* SLH-DSA n-value table indexed by (param_set - 1) */
#define CMH_SLHDSA_N_128		16U
#define CMH_SLHDSA_N_192		24U
#define CMH_SLHDSA_N_256		32U

/* SLH-DSA key sizes: pk = 2*n, sk = 4*n, seed = 3*n */
#define CMH_SLHDSA_PK_SIZE(n)		(2U * (n))
#define CMH_SLHDSA_SK_SIZE(n)		(4U * (n))
#define CMH_SLHDSA_SEED_SIZE(n)		(3U * (n))

/* SLH-DSA signature sizes indexed by (param_set - 1) */
#define CMH_SLHDSA_SIG_SIZE_SHAKE_128S	7856U
#define CMH_SLHDSA_SIG_SIZE_SHAKE_128F	17088U
#define CMH_SLHDSA_SIG_SIZE_SHAKE_192S	16224U
#define CMH_SLHDSA_SIG_SIZE_SHAKE_192F	35664U
#define CMH_SLHDSA_SIG_SIZE_SHAKE_256S	29792U
#define CMH_SLHDSA_SIG_SIZE_SHAKE_256F	49856U
#define CMH_SLHDSA_SIG_SIZE_SHA2_128S	7856U
#define CMH_SLHDSA_SIG_SIZE_SHA2_128F	17088U
#define CMH_SLHDSA_SIG_SIZE_SHA2_192S	16224U
#define CMH_SLHDSA_SIG_SIZE_SHA2_192F	35664U
#define CMH_SLHDSA_SIG_SIZE_SHA2_256S	29792U
#define CMH_SLHDSA_SIG_SIZE_SHA2_256F	49856U

/* -- PKE curve IDs -------------- */

#define CMH_CURVE_P192			0x01U
#define CMH_CURVE_P224			0x02U
#define CMH_CURVE_P256			0x03U
#define CMH_CURVE_P384			0x04U
#define CMH_CURVE_P521			0x05U
#define CMH_CURVE_SECP256K1		0x07U
#define CMH_CURVE_BP192R1		0x11U
#define CMH_CURVE_BP224R1		0x12U
#define CMH_CURVE_BP256R1		0x13U
#define CMH_CURVE_BP320R1		0x14U
#define CMH_CURVE_BP384R1		0x15U
#define CMH_CURVE_BP512R1		0x16U
#define CMH_CURVE_SM2			0x18U
#define CMH_CURVE_25519			0x21U
#define CMH_CURVE_448			0x22U

/* ML-KEM */

struct cmh_ioctl_ml_kem_keygen {
	__u32 version;
	__u32 k;		/* security parameter: 2/3/4 */
	__u32 flags;		/* CMH_QSE_FLAG_* */
	__u32 __reserved;
	__u64 seed;		/* user-space pointer to seed (or 0 for HW RNG) */
	__u64 z;		/* user-space pointer to z (or 0 for HW RNG) */
	__u64 ek;		/* [out] user-space pointer to encapsulation key */
	__u64 dk;		/* [out] user-space pointer to decapsulation key
				 * or [out] DS ref if CMH_QSE_FLAG_DS_REF
				 */
	__u64 dk_cid;		/* CID for DS entry (if DS_REF) */
	__u64 dk_ref;		/* [out] dk DS reference (if DS_REF) */
};

struct cmh_ioctl_ml_kem_enc {
	__u32 version;
	__u32 k;
	__u32 flags;		/* CMH_QSE_FLAG_* */
	__u32 __reserved;
	__u64 coin;		/* user-space pointer to random coin (or 0) */
	__u64 ek;		/* user-space pointer to encapsulation key */
	__u64 ct;		/* [out] user-space pointer to ciphertext */
	__u64 ss;		/* [out] user-space pointer to shared secret */
	__u64 __reserved2[2];	/* reserved for future use */
};

struct cmh_ioctl_ml_kem_dec {
	__u32 version;
	__u32 k;
	__u32 flags;		/* CMH_QSE_FLAG_* */
	__u32 __reserved;
	__u64 ct;		/* user-space pointer to ciphertext */
	__u64 dk;		/* user-space pointer to dk or DS ref */
	__u64 ss;		/* [out] user-space pointer to shared secret */
	__u64 __reserved2[2];	/* reserved for future use */
};

/* ML-DSA */

struct cmh_ioctl_ml_dsa_keygen {
	__u32 version;
	__u32 mode;		/* security parameter: 2/3/5 */
	__u32 flags;		/* CMH_QSE_FLAG_* */
	__u32 __reserved;
	__u64 seed;		/* user-space pointer to seed (or 0 for HW RNG) */
	__u64 pk;		/* [out] user-space pointer to public key */
	__u64 sk;		/* [out] user-space pointer to secret key
				 * or [out] DS ref if CMH_QSE_FLAG_DS_REF
				 */
	__u64 sk_cid;		/* CID for DS entry (if DS_REF) */
	__u64 sk_ref;		/* [out] sk DS reference (if DS_REF) */
};

struct cmh_ioctl_ml_dsa_sign {
	__u32 version;
	__u32 mode;
	__u32 flags;		/* CMH_QSE_FLAG_* */
	__u32 mlen;		/* message length in bytes */
	__u64 m;		/* user-space pointer to message */
	__u64 sk;		/* user-space pointer to sk or DS ref */
	__u64 sig;		/* [out] user-space pointer to signature */
	__u64 rnd;		/* user-space pointer to randomness (or 0) */
};

/* SLH-DSA */

struct cmh_ioctl_slhdsa_keygen {
	__u32 version;
	__u32 parameter_set;	/* HCQ_SLHDSA_SHAKE_128S .. SHA2_256F */
	__u32 flags;		/* CMH_QSE_FLAG_DS_REF */
	__u32 __reserved;
	__u64 seed;		/* user-space pointer to seed */
	__u64 pk;		/* [out] user-space pointer to public key */
	__u64 sk;		/* [out] user-space pointer to secret key
				 * or [out] DS ref if CMH_QSE_FLAG_DS_REF
				 */
	__u64 sk_cid;		/* CID for DS entry (if DS_REF) */
	__u64 sk_ref;		/* [out] sk DS reference (if DS_REF) */
};

struct cmh_ioctl_slhdsa_sign {
	__u32 version;
	__u32 parameter_set;
	__u32 msg_len;
	__u32 ctx_len;
	__u64 msg;		/* user-space pointer to message */
	__u64 ctx;		/* user-space pointer to context (or 0) */
	__u64 sk;		/* DS ref for secret key */
	__u64 sig;		/* [out] user-space pointer to signature */
	__u64 add_random;	/* user-space pointer to addl. randomness (or 0) */
};

struct cmh_ioctl_slhdsa_sign_prehash {
	__u32 version;
	__u32 parameter_set;
	__u32 prehash_algo;	/* CMH_SLHDSA_PREHASH_* */
	__u32 digest;		/* 0 = raw msg (eSW hashes), 1 = pre-computed digest */
	__u32 msg_len;
	__u32 ctx_len;
	__u64 msg;		/* user-space pointer to message/digest */
	__u64 ctx;		/* user-space pointer to context (or 0) */
	__u64 sk;		/* DS ref for secret key */
	__u64 sig;		/* [out] user-space pointer to signature */
	__u64 add_random;	/* user-space pointer to addl. randomness (or 0) */
};

/* -- SM2 ioctl argument structures ----------- */

/* SM2 fixed key sizes (sm2p256v1 curve, 256-bit) */
#define CMH_SM2_CLEN			32U	/* coordinate length */
#define CMH_SM2_PUBKEY_LEN		64U	/* uncompressed (x||y) */
#define CMH_SM2_POINT_LEN		64U	/* EC point (x||y) */
#define CMH_SM2_SHARED_KEY_LEN		16U	/* ECDH shared key */
#define CMH_SM2_DIGEST_LEN		32U	/* SM3 digest (ZA) */
/*
 * SM2 enc_hash/dec_hash payload limit.
 *
 * The eSW PKE driver implements only a single-block GM/T 0003.4 KDF
 * (one SM3 invocation, 32 bytes of key stream).  Longer messages would
 * silently produce incorrect ciphertext / plaintext, so the driver caps
 * the payload at 32 bytes.  See Documentation/ABI/testing/cmh-mgmt.
 */
#define CMH_SM2_MAX_MSG_LEN		32U	/* encrypt/decrypt */
#define CMH_SM2_MAX_ID_LEN		32U	/* identity string */
#define CMH_SM2_CT_OVERHEAD		96U	/* C1(64) + C3(32) */
#define CMH_SM2_MAX_CT_LEN		128U	/* 96 + max_msg = 128 */

struct cmh_ioctl_sm2_ecdh_keygen {
	__u32 version;
	__u32 nonce_len;	/* 0 = HW generates r (written back), 32 = caller provides r */
	__u64 nonce;		/* [in/out] user-space pointer to nonce buffer (32B) */
	__u64 session_key;	/* [out] user-space pointer to session key R=r*G (64B) */
};

struct cmh_ioctl_sm2_ecdh {
	__u32 version;
	__u32 nonce_len;	/* 0 = HW generates (written back), 32 = caller provides */
	__u64 nonce;		/* [in/out] user-space pointer to nonce r (32B) */
	__u64 peer_public_key;	/* user-space pointer to peer pub key (64B) */
	__u64 peer_session_key;	/* user-space pointer to peer session key (64B) */
	__u64 key_ref;		/* private key DS reference */
	__u64 shared_point;	/* [out] user-space pointer to shared point (64B) */
	__u64 shared_point_ref;	/* [in/out] 0 = read-back mode; &ref = keep DS, write ref */
};

struct cmh_ioctl_sm2_dec_point {
	__u32 version;
	__u32 ciphertext_len;	/* total ciphertext length (97..128) */
	__u64 ciphertext;	/* user-space pointer to ciphertext (64B: C1) */
	__u64 dec_point;	/* [out] user-space pointer to dec point (64B) */
	__u64 key_ref;		/* private key DS reference */
};

struct cmh_ioctl_sm2_enc_point {
	__u32 version;
	__u32 nonce_len;	/* 0 = HW generates, 32 = caller provides */
	__u64 nonce;		/* user-space pointer to nonce (or 0) */
	__u64 public_key;	/* user-space pointer to public key (64B) */
	__u64 ciphertext;	/* [out] user-space pointer to C1 (64B) */
	__u64 enc_point;	/* [out] user-space pointer to enc point (64B) */
};

struct cmh_ioctl_sm2_id_digest {
	__u32 version;
	__u32 id_len;		/* identity length in bytes (<=32) */
	__u64 id;		/* user-space pointer to identity string */
	__u64 public_key;	/* user-space pointer to public key (64B) */
	__u64 digest;		/* [out] user-space pointer to ZA digest (32B) */
};

/*
 * SM2 ECDH_HASH -- derive shared key from shared point + ZA digests.
 *
 * IMPORTANT: The digest fields use ABSOLUTE ordering per GM/T 0003.3,
 * NOT relative own/peer ordering.  Both parties must pass:
 *   peer_id_digest = Z_A (initiator's digest) -- hashed FIRST
 *   id_digest      = Z_B (responder's digest) -- hashed SECOND
 * The eSW computes: KDF(shared_point || peer_id_digest || id_digest).
 */
struct cmh_ioctl_sm2_ecdh_hash {
	__u32 version;
	__u32 __reserved;
	__u64 peer_id_digest;	/* ptr to Z_A -- initiator's digest (32B) */
	__u64 id_digest;	/* ptr to Z_B -- responder's digest (32B) */
	__u64 shared_point_ref;	/* DS reference from SM2_ECDH */
	__u64 shared_key;	/* [out] ptr to shared key (16B) */
};

struct cmh_ioctl_sm2_dec_hash {
	__u32 version;
	__u32 ciphertext_len;	/* ciphertext length (97..128) */
	__u64 ciphertext;	/* user-space pointer to full ciphertext */
	__u64 dec_point;	/* user-space pointer to dec point (64B) */
	__u64 plaintext;	/* [out] user-space pointer to plaintext */
};

struct cmh_ioctl_sm2_enc_hash {
	__u32 version;
	__u32 message_len;	/* message length (1..32) */
	__u64 message;		/* user-space pointer to plaintext */
	__u64 enc_point;	/* user-space pointer to enc point (64B) */
	__u64 ciphertext;	/* [out] user-space pointer to ciphertext */
};

/* PQC ioctl numbers */
#define CMH_IOCTL_ML_KEM_KEYGEN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x20, \
					struct cmh_ioctl_ml_kem_keygen)
#define CMH_IOCTL_ML_KEM_ENC		_IOWR(CMH_MGMT_IOC_MAGIC, 0x21, \
					struct cmh_ioctl_ml_kem_enc)
#define CMH_IOCTL_ML_KEM_DEC		_IOWR(CMH_MGMT_IOC_MAGIC, 0x22, \
					struct cmh_ioctl_ml_kem_dec)
#define CMH_IOCTL_ML_DSA_KEYGEN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x23, \
					struct cmh_ioctl_ml_dsa_keygen)
#define CMH_IOCTL_ML_DSA_SIGN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x24, \
					struct cmh_ioctl_ml_dsa_sign)
#define CMH_IOCTL_SLHDSA_KEYGEN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x28, \
					struct cmh_ioctl_slhdsa_keygen)
#define CMH_IOCTL_SLHDSA_SIGN		_IOWR(CMH_MGMT_IOC_MAGIC, 0x29, \
					struct cmh_ioctl_slhdsa_sign)
#define CMH_IOCTL_SLHDSA_SIGN_PREHASH	_IOWR(CMH_MGMT_IOC_MAGIC, 0x2D, \
					struct cmh_ioctl_slhdsa_sign_prehash)

/* SM2 operation ioctls */
#define CMH_IOCTL_SM2_ECDH_KEYGEN	_IOWR(CMH_MGMT_IOC_MAGIC, 0x30, \
					struct cmh_ioctl_sm2_ecdh_keygen)
#define CMH_IOCTL_SM2_ECDH		_IOWR(CMH_MGMT_IOC_MAGIC, 0x31, \
					struct cmh_ioctl_sm2_ecdh)
#define CMH_IOCTL_SM2_DEC_POINT		_IOWR(CMH_MGMT_IOC_MAGIC, 0x32, \
					struct cmh_ioctl_sm2_dec_point)
#define CMH_IOCTL_SM2_ENC_POINT		_IOWR(CMH_MGMT_IOC_MAGIC, 0x33, \
					struct cmh_ioctl_sm2_enc_point)
#define CMH_IOCTL_SM2_ID_DIGEST		_IOWR(CMH_MGMT_IOC_MAGIC, 0x34, \
					struct cmh_ioctl_sm2_id_digest)
#define CMH_IOCTL_SM2_ECDH_HASH		_IOWR(CMH_MGMT_IOC_MAGIC, 0x35, \
					struct cmh_ioctl_sm2_ecdh_hash)
#define CMH_IOCTL_SM2_DEC_HASH		_IOWR(CMH_MGMT_IOC_MAGIC, 0x36, \
					struct cmh_ioctl_sm2_dec_hash)
#define CMH_IOCTL_SM2_ENC_HASH		_IOWR(CMH_MGMT_IOC_MAGIC, 0x37, \
					struct cmh_ioctl_sm2_enc_hash)

/*
 * EAC (Error and Alarm Controller) -- read and clear error registers.
 *
 * Returns a snapshot of all hardware error/safety/notification registers.
 * The eSW atomically reads and clears the registers on each call, so
 * successive reads show only new events.
 */
struct cmh_ioctl_eac_read {
	__u32 version;			/* must be CMH_MGMT_V1 */
	__u32 __reserved;
	__u64 mailbox_notification;	/* [out] MBX safety notification bitmask */
	__u32 hw_error;			/* [out] HWC error bitmask */
	__u32 hw_nmi;			/* [out] HWC NMI bitmask */
	__u32 hw_panic;			/* [out] HWC panic bitmask */
	__u32 safety_fatal;		/* [out] HWC fatal safety bitmask */
	__u32 safety_notification;	/* [out] HWC safety notification bitmask */
	__u32 sw_info0;			/* [out] eSW tracing info */
	__u32 sw_info1;			/* [out] eSW tracing info */
	__u32 sram_bank_errors[4];	/* [out] correctable ECC error counts */
	__u32 __pad;			/* explicit tail padding (prevent info leak) */
};

/*
 * DRBG CONFIG -- configure the hardware DRBG before first use.
 *
 * This is a management operation normally performed once at system
 * start-up.  Must be called before any hwrng reads or DRBG GENERATE
 * operations.
 */
#define CMH_DRBG_RATIO_ONE		0	/* 1:1 entropy ratio */
#define CMH_DRBG_RATIO_ONE_HALF		1	/* 1:2 */
#define CMH_DRBG_RATIO_ONE_THIRD	2	/* 1:3 */
#define CMH_DRBG_RATIO_ONE_FOURTH	3	/* 1:4 */

#define CMH_DRBG_STRENGTH_128		0x00	/* 128-bit security */
#define CMH_DRBG_STRENGTH_256		0x10	/* 256-bit security */

struct cmh_ioctl_drbg_config {
	__u32 version;			/* must be CMH_MGMT_V1 */
	__u32 entropy_ratio;		/* CMH_DRBG_RATIO_* */
	__u32 security_strength;	/* CMH_DRBG_STRENGTH_* */
	__u32 __reserved;
};

/* EAC ioctl number */
#define CMH_IOCTL_EAC_READ		_IOWR(CMH_MGMT_IOC_MAGIC, 0x0F, \
					struct cmh_ioctl_eac_read)

/* DRBG management ioctl number */
#define CMH_IOCTL_DRBG_CONFIG		_IOW(CMH_MGMT_IOC_MAGIC, 0x40, \
					struct cmh_ioctl_drbg_config)

#endif /* _UAPI_CMH_MGMT_IOCTL_H */
