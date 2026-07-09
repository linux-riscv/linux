/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- PKE Common Types and Helpers
 *
 * Shared definitions for RSA, ECDSA, ECDH, EdDSA, and SM2 drivers.
 * Curve -> coordinate-length mapping, VCQ byte-swap flags, and
 * common VCQ builder prototypes.
 */

#ifndef CMH_PKE_H
#define CMH_PKE_H

#include <linux/types.h>
#include "cmh_vcq.h"
#include "cmh_pke_abi.h"

/* VCQ byte-swap flags for DMA transfers (per CMH VCQ ABI) */
#define VCQ_FLAG_SWAP_BYTES	0x400000U
#define VCQ_FLAG_SWAP_WORDS	0x200000U

/* VCQ byte-swap flags for PKE -- big-endian data on LE bus */
#define PKE_SWAP_FLAGS	(VCQ_FLAG_SWAP_BYTES | VCQ_FLAG_SWAP_WORDS)

/* VCQ layout: header + [SYS_WRITE] + PKE_CMD + flush */
#define PKE_VCQ_CMDS_MIN	3	/* header + cmd + flush */
#define PKE_VCQ_CMDS_MAX	4	/* header + SYS_WRITE + cmd + flush */

/* Max RSA key size in bytes (4096 bits) */
#define PKE_RSA_MAX_BYTES	512
#define PKE_RSA_MIN_BITS	1024
#define PKE_RSA_MAX_BITS	4096

/* EdDSA SCA: Ed448 blinded private key length (bytes) */
#define PKE_ED448_SK_SCA_LEN	226

/**
 * pke_curve_clen() - Get EC curve coordinate length in bytes
 * @curve: PKE curve identifier (PKE_CURVE_*)
 *
 * Return: Coordinate length in bytes, or 0 for unknown curves.
 */
static inline u32 pke_curve_clen(u32 curve)
{
	switch (curve) {
	case PKE_CURVE_P192:
	case PKE_CURVE_BP192R1:
		return 24;
	case PKE_CURVE_P224:
	case PKE_CURVE_BP224R1:
		return 28;
	case PKE_CURVE_P256:
	case PKE_CURVE_SECP256K1:
	case PKE_CURVE_BP256R1:
	case PKE_CURVE_ANSSI_FRP256V1:
	case PKE_CURVE_SM2:
	case PKE_CURVE_25519:
		return 32;
	case PKE_CURVE_BP320R1:
		return 40;
	case PKE_CURVE_P384:
	case PKE_CURVE_BP384R1:
		return 48;
	case PKE_CURVE_BP512R1:
		return 64;
	case PKE_CURVE_P521:
		return 68; /* ceil(521/8) = 66, ABI uses ALIGN(66, 4) = 68 */
	case PKE_CURVE_448:
		return 56;
	default:
		return 0;
	}
}

/**
 * pke_curve_bits() - Get EC curve size in bits
 * @curve: PKE curve identifier (PKE_CURVE_*)
 *
 * Return: Curve size in bits, or 0 for unknown curves.
 */
static inline u32 pke_curve_bits(u32 curve)
{
	switch (curve) {
	case PKE_CURVE_P192:
	case PKE_CURVE_BP192R1:
		return 192;
	case PKE_CURVE_P224:
	case PKE_CURVE_BP224R1:
		return 224;
	case PKE_CURVE_P256:
	case PKE_CURVE_SECP256K1:
	case PKE_CURVE_BP256R1:
	case PKE_CURVE_ANSSI_FRP256V1:
	case PKE_CURVE_SM2:
	case PKE_CURVE_25519:
		return 256;
	case PKE_CURVE_BP320R1:
		return 320;
	case PKE_CURVE_P384:
	case PKE_CURVE_BP384R1:
		return 384;
	case PKE_CURVE_BP512R1:
		return 512;
	case PKE_CURVE_P521:
		return 521;
	case PKE_CURVE_448:
		return 448;
	default:
		return 0;
	}
}

/**
 * pke_eddsa_key_len() - Get EdDSA key/pubkey length
 * @curve: PKE curve identifier (PKE_CURVE_25519 or PKE_CURVE_448)
 *
 * Ed25519 uses 32 bytes (== clen), Ed448 uses 57 bytes (clen + 1
 * flag byte per RFC 8032).  Signature length is 2 * pke_eddsa_key_len().
 *
 * Return: Key length in bytes.
 */
static inline u32 pke_eddsa_key_len(u32 curve)
{
	u32 clen = pke_curve_clen(curve);

	return (curve == PKE_CURVE_448) ? clen + 1 : clen;
}

/**
 * pke_curve_is_edwards() - Check if curve uses Edwards form
 * @curve: PKE curve identifier (PKE_CURVE_*)
 *
 * Return: true for Curve25519 and Curve448, false otherwise.
 */
static inline bool pke_curve_is_edwards(u32 curve)
{
	return curve == PKE_CURVE_25519 || curve == PKE_CURVE_448;
}

/**
 * pke_swap_flags() - Get VCQ byte-swap flags for a given curve
 * @curve: PKE curve identifier (PKE_CURVE_*)
 *
 * Weierstrass curves need byte+word swap; Edwards curves do not.
 *
 * Return: VCQ swap flags to OR into the command ID.
 */
static inline u32 pke_swap_flags(u32 curve)
{
	return pke_curve_is_edwards(curve) ? 0 : PKE_SWAP_FLAGS;
}

/* Common VCQ builder prototypes */

void vcq_add_pke_flush(struct vcq_cmd *slot, u32 core_id);

void vcq_add_pke_rsa_enc(struct vcq_cmd *slot, u32 core_id, u32 bits, u32 e_len,
			 u64 e_dma, u64 n_dma, u64 m_dma, u64 c_dma,
			 u32 flags);

void vcq_add_pke_rsa_dec(struct vcq_cmd *slot, u32 core_id, u32 bits, u32 e_len,
			 u64 e_dma, u64 n_dma, u64 c_dma, u64 m_dma,
			 u64 d_ref, u32 flags);

void vcq_add_pke_rsa_crt_dec(struct vcq_cmd *slot, u32 core_id, u32 bits, u32 e_len,
			     u64 e_dma, u64 n_dma, u64 c_dma, u64 m_dma,
			     u64 crt_ref, u32 flags);

void vcq_add_pke_ecdsa_verify(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 dlen,
			      u64 pk_dma, u64 dig_dma, u64 sig_dma,
			      u64 rp_dma, u32 flags);

void vcq_add_pke_ecdsa_sign(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			    u64 dig_dma, u64 sig_dma, u64 sk_ref,
			    u32 dlen, u32 flags);

void vcq_add_pke_ecdsa_pubgen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			      u64 pk_dma, u64 sk_ref, u32 flags);

void vcq_add_pke_ecdsa_keygen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			      u64 sk_ref, u32 sk_type, u32 flags);

void vcq_add_pke_ecdh_keygen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			     u64 pkx_dma, u64 sk_ref, u32 flags);

void vcq_add_pke_ecdh(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
		      u32 sslen, u32 ss_type, u64 peer_dma, u64 sk_ref,
		      u64 ss_ref, u32 flags);

void vcq_add_pke_eddsa_verify(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 dlen,
			      u64 pky_dma, u64 dig_dma, u64 sig_dma,
			      u64 rp_dma, u32 flags);

void vcq_add_pke_eddsa_sign(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			    u64 dig_dma, u64 sig_dma, u64 sk_ref,
			    u32 dlen, u32 flags);

void vcq_add_pke_eddsa_pubgen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			      u64 pky_dma, u64 sk_ref, u32 flags);

void vcq_add_pke_eddsa_keygen_sca(struct vcq_cmd *slot, u32 core_id, u32 curve,
				  u64 sk_ref, u64 sca_sk_ref);

/* SM2 VCQ builders */

void vcq_add_pke_sm2_ecdh_keygen(struct vcq_cmd *slot, u32 core_id, u64 nonce_dma,
				 u64 session_key_dma, u32 nonce_len, u32 flags);

void vcq_add_pke_sm2_ecdh(struct vcq_cmd *slot, u32 core_id, u32 nonce_len,
			  u32 private_key_len, u64 nonce_dma,
			  u64 peer_pk_dma, u64 peer_sk_dma,
			  u64 priv_ref, u64 sp_ref, u32 sp_type, u32 flags);

void vcq_add_pke_sm2_dec_point(struct vcq_cmd *slot, u32 core_id, u32 ct_len,
			       u32 pk_len, u64 ct_dma, u64 dp_dma,
			       u64 priv_ref, u32 flags);

void vcq_add_pke_sm2_enc_point(struct vcq_cmd *slot, u32 core_id, u64 nonce_dma,
			       u64 pk_dma, u64 ct_dma, u64 ep_dma,
			       u32 nonce_len, u32 flags);

void vcq_add_pke_sm2_id_digest(struct vcq_cmd *slot, u32 core_id, u64 id_dma,
			       u64 pk_dma, u64 dig_dma, u32 id_len,
			       u32 flags);

void vcq_add_pke_sm2_ecdh_hash(struct vcq_cmd *slot, u32 core_id, u64 peer_dig_dma,
			       u64 dig_dma, u64 sp_ref, u64 sk_ref,
			       u32 sk_type, u32 flags);

void vcq_add_pke_sm2_dec_hash(struct vcq_cmd *slot, u32 core_id, u64 ct_dma,
			      u64 dp_dma, u64 pt_dma, u32 ct_len, u32 flags);

void vcq_add_pke_sm2_enc_hash(struct vcq_cmd *slot, u32 core_id, u64 msg_dma,
			      u64 ep_dma, u64 ct_dma, u32 msg_len, u32 flags);

/* Registration */

int cmh_pke_rsa_register(void);
void cmh_pke_rsa_unregister(void);
int cmh_pke_ecdsa_register(void);
void cmh_pke_ecdsa_unregister(void);
int cmh_pke_ecdh_register(void);
void cmh_pke_ecdh_unregister(void);

#endif /* CMH_PKE_H */
