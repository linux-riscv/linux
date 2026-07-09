/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- PKE Core ABI Definitions
 *
 * Kernel-side definitions for the CMH PKE ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_PKE_ABI_H
#define CMH_PKE_ABI_H

#include <linux/types.h>

/* PKE Command IDs */

#define PKE_CMD_ECDSA_VERIFY		0x03U
#define PKE_CMD_ECDSA_SIGN		0x04U
#define PKE_CMD_ECDSA_PUBGEN		0x05U
#define PKE_CMD_ECDSA_KEYGEN		0x06U
#define PKE_CMD_EDDSA_VERIFY		0x07U
#define PKE_CMD_EDDSA_SIGN		0x08U
#define PKE_CMD_EDDSA_PUBGEN		0x09U
#define PKE_CMD_ECDH_KEYGEN		0x0AU
#define PKE_CMD_ECDH			0x0BU
#define PKE_CMD_RSA_ENC			0x0CU
#define PKE_CMD_RSA_DEC			0x0DU
#define PKE_CMD_RSA_KEYGEN		0x0EU
#define PKE_CMD_RSA_CRT_DEC		0x0FU
#define PKE_CMD_SM2_ECDH_KEYGEN		0x16U
#define PKE_CMD_SM2_ECDH		0x17U
#define PKE_CMD_SM2_DEC_POINT		0x18U
#define PKE_CMD_SM2_ENC_POINT		0x19U
#define PKE_CMD_SM2_ID_DIGEST		0x1AU
#define PKE_CMD_SM2_ECDH_HASH		0x1BU
#define PKE_CMD_SM2_DEC_HASH		0x1CU
#define PKE_CMD_SM2_ENC_HASH		0x1DU
#define PKE_CMD_EDDSA_PRIV_KEYGEN_SCA	0x21U
#define PKE_CMD_FLUSH			0xFFU

/* EC Curve IDs (per CMH PKE ABI) */

#define PKE_CURVE_P192			0x01U
#define PKE_CURVE_P224			0x02U
#define PKE_CURVE_P256			0x03U
#define PKE_CURVE_P384			0x04U
#define PKE_CURVE_P521			0x05U
#define PKE_CURVE_SECP256K1		0x07U
#define PKE_CURVE_BP192R1		0x11U
#define PKE_CURVE_BP224R1		0x12U
#define PKE_CURVE_BP256R1		0x13U
#define PKE_CURVE_BP320R1		0x14U
#define PKE_CURVE_BP384R1		0x15U
#define PKE_CURVE_BP512R1		0x16U
#define PKE_CURVE_ANSSI_FRP256V1	0x17U
#define PKE_CURVE_SM2			0x18U
#define PKE_CURVE_25519			0x21U
#define PKE_CURVE_448			0x22U

/* PKE Command Structures -- match CMH eSW ABI exactly */

struct pke_cmd_ecdsa_verify {
	u32 curve;
	u32 digest_len;
	u64 public_key;
	u64 digest;
	u64 signature;
	u64 rprime;
};

struct pke_cmd_ecdsa_sign {
	u32 curve;
	u32 secret_key_len;
	u64 digest;
	u64 signature;
	u64 secret_key;		/* DS reference */
	u32 digest_len;
};

struct pke_cmd_ecdsa_pubgen {
	u32 curve;
	u32 secret_key_len;
	u64 public_key;
	u64 secret_key;		/* DS reference */
};

struct pke_cmd_ecdsa_keygen {
	u32 curve;
	u32 secret_key_len;
	u64 secret_key;		/* DS reference */
	u32 secret_key_type;
};

struct pke_cmd_eddsa_verify {
	u32 curve;
	u32 digest_len;
	u64 public_key_y;
	u64 digest;
	u64 signature;
	u64 rprime;
};

struct pke_cmd_eddsa_sign {
	u32 curve;
	u32 secret_key_len;
	u64 digest;
	u64 signature;
	u64 secret_key;		/* DS reference */
	u32 digest_len;
};

struct pke_cmd_eddsa_pubgen {
	u32 curve;
	u32 secret_key_len;
	u64 public_key_y;
	u64 secret_key;		/* DS reference */
};

struct pke_cmd_ecdh_keygen {
	u32 curve;
	u32 secret_key_len;
	u64 public_key_x;
	u64 secret_key;		/* DS reference */
};

struct pke_cmd_ecdh {
	u32 curve;
	u32 secret_key_len;
	u32 shared_secret_len;
	u32 shared_secret_type;
	u64 peer_key_x;
	u64 secret_key;		/* DS reference */
	u64 shared_secret;	/* DS reference for result */
};

struct pke_cmd_rsa_enc {
	u32 bits;
	u32 e_len;
	u64 e;
	u64 n;
	u64 m;
	u64 c;
};

struct pke_cmd_rsa_dec {
	u32 bits;
	u32 e_len;
	u64 e;
	u64 n;
	u64 c;
	u64 m;
	u64 d;			/* DS reference */
};

struct pke_cmd_rsa_crt_dec {
	u32 bits;
	u32 e_len;
	u64 e;
	u64 n;
	u64 c;
	u64 m;
	u64 crt;		/* DS reference */
};

struct pke_cmd_rsa_keygen {
	u32 bits;
	u32 d_type;
	u64 e;
	u64 n;
	u64 d;			/* DS reference */
	u64 crt;		/* DS reference */
	u32 crt_type;
};

struct pke_cmd_eddsa_keygen_sca {
	u32 curve;
	u64 secret_key;		/* DS reference: input normal SK */
	u64 sca_secret_key;	/* DS reference: output blinded SK */
};

/* SM2 Command Structures */

struct pke_cmd_sm2_ecdh_keygen {
	u64 nonce;		/* DMA addr (32B input or output) */
	u64 session_key;	/* DMA addr output (64B) */
	u32 nonce_len;		/* 0 = HW generates, 32 = caller provides */
};

struct pke_cmd_sm2_ecdh {
	u32 nonce_len;		/* 0 or 32 */
	u32 private_key_len;	/* must be 32 */
	u64 nonce;		/* DMA addr (32B) */
	u64 peer_public_key;	/* DMA addr (64B) */
	u64 peer_session_key;	/* DMA addr (64B) */
	u64 private_key;		/* DS reference */
	u64 shared_point;	/* DS reference (output, 64B) */
	u32 shared_point_type;	/* SYS_TYPE_SET(flags, CORE_ID_PKE) */
};

struct pke_cmd_sm2_dec_point {
	u32 ciphertext_len;	/* total CT length (97..128) */
	u32 private_key_len;	/* must be 32 */
	u64 ciphertext;		/* DMA addr (64B: C1 point) */
	u64 dec_point;		/* DMA addr output (64B) */
	u64 private_key;		/* DS reference */
};

struct pke_cmd_sm2_enc_point {
	u64 nonce;		/* DMA addr (32B, optional) */
	u64 public_key;		/* DMA addr (64B) */
	u64 ciphertext;		/* DMA addr output (64B: C1) */
	u64 enc_point;		/* DMA addr output (64B) */
	u32 nonce_len;		/* 0 or 32 */
};

struct pke_cmd_sm2_id_digest {
	u64 id;			/* DMA addr (identity, <=32B) */
	u64 public_key;		/* DMA addr (64B) */
	u64 digest;		/* DMA addr output (32B) */
	u32 id_len;		/* identity length in bytes */
};

struct pke_cmd_sm2_ecdh_hash {
	u64 peer_id_digest;	/* DMA addr (32B) */
	u64 id_digest;		/* DMA addr (32B) */
	u64 shared_point;	/* DS reference (64B input) */
	u64 shared_key;		/* DS reference (16B output) */
	u32 shared_key_type;	/* SYS_TYPE_SET(flags, CORE_ID_PKE) */
};

struct pke_cmd_sm2_dec_hash {
	u64 ciphertext;		/* DMA addr (full ciphertext) */
	u64 dec_point;		/* DMA addr (64B) */
	u64 plaintext;		/* DMA addr output (ct_len - 96 bytes) */
	u32 ciphertext_len;	/* 97..128 */
};

struct pke_cmd_sm2_enc_hash {
	u64 message;		/* DMA addr (plaintext) */
	u64 enc_point;		/* DMA addr (64B) */
	u64 ciphertext;		/* DMA addr output (96 + msg_len) */
	u32 message_len;	/* 1..32 */
};

/* PKE Command Union */

union pke_cmd {
	struct pke_cmd_ecdsa_verify	cmd_ecdsa_verify;
	struct pke_cmd_ecdsa_sign	cmd_ecdsa_sign;
	struct pke_cmd_ecdsa_pubgen	cmd_ecdsa_pubgen;
	struct pke_cmd_ecdsa_keygen	cmd_ecdsa_keygen;
	struct pke_cmd_eddsa_verify	cmd_eddsa_verify;
	struct pke_cmd_eddsa_sign	cmd_eddsa_sign;
	struct pke_cmd_eddsa_pubgen	cmd_eddsa_pubgen;
	struct pke_cmd_ecdh_keygen	cmd_ecdh_keygen;
	struct pke_cmd_ecdh		cmd_ecdh;
	struct pke_cmd_rsa_enc		cmd_rsa_enc;
	struct pke_cmd_rsa_dec		cmd_rsa_dec;
	struct pke_cmd_rsa_crt_dec	cmd_rsa_crt_dec;
	struct pke_cmd_rsa_keygen	cmd_rsa_keygen;
	struct pke_cmd_eddsa_keygen_sca	cmd_eddsa_keygen_sca;
	struct pke_cmd_sm2_ecdh_keygen	cmd_sm2_ecdh_keygen;
	struct pke_cmd_sm2_ecdh		cmd_sm2_ecdh;
	struct pke_cmd_sm2_dec_point	cmd_sm2_dec_point;
	struct pke_cmd_sm2_enc_point	cmd_sm2_enc_point;
	struct pke_cmd_sm2_id_digest	cmd_sm2_id_digest;
	struct pke_cmd_sm2_ecdh_hash	cmd_sm2_ecdh_hash;
	struct pke_cmd_sm2_dec_hash	cmd_sm2_dec_hash;
	struct pke_cmd_sm2_enc_hash	cmd_sm2_enc_hash;
};

#endif /* CMH_PKE_ABI_H */
