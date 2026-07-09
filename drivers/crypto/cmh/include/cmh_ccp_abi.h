/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- CCP Core ABI Definitions
 *
 * Kernel-side definitions for the CMH CCP ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 *
 * The CCP core provides three modes:
 *   - ChaCha20 stream cipher (skcipher)
 *   - Poly1305 one-time authenticator (shash)
 *   - ChaCha20-Poly1305 AEAD (RFC 7539)
 */

#ifndef CMH_CCP_ABI_H
#define CMH_CCP_ABI_H

#include <linux/types.h>

/* CCP Block Sizes */

#define CCP_CHACHA_BLOCK_SIZE	64U	/* ChaCha20 block = 512 bits */
#define CCP_POLY_BLOCK_SIZE	16U	/* Poly1305 block = 128 bits */
#define CCP_CTRNONCE_SIZE	16U	/* 4-byte LE counter + 12-byte nonce */
#define CCP_POLY_KEY_SIZE	16U	/* r_key and s_key each 16 bytes */
#define CCP_POLY_TAG_SIZE	16U	/* Poly1305 tag = 128 bits */
#define CCP_CHACHA_CTR_LEN	4U	/* 32-bit counter */

/* CCP Operations (per CMH CCP ABI) */

#define CCP_OP_DECRYPT		1U
#define CCP_OP_ENCRYPT		2U

/* CCP Command IDs */

#define CCP_CMD_CHACHA20_INIT	0x01U
#define CCP_CMD_POLY1305_INIT	0x02U
#define CCP_CMD_AEAD_INIT	0x03U
#define CCP_CMD_AAD_UPDATE	0x04U
#define CCP_CMD_AAD_FINAL	0x05U
#define CCP_CMD_UPDATE		0x06U
#define CCP_CMD_FINAL		0x07U
#define CCP_CMD_SCATTERGATHER	0x08U
/* CCP_CMD_FLUSH = VCQ_CMD_FLUSH (0xFF) -- defined in cmh_vcq.h */

/* CCP Command Structures */

struct ccp_cmd_chacha {
	u64 key;		/* datastore reference for the key */
	u64 ctrnonce;		/* DMA address of the 16-byte counter+nonce */
	u32 keylen;		/* key length: 16 or 32 bytes */
	u32 ctrnoncelen;	/* always 16 */
	u32 ctrlen;		/* counter length: 4 bytes */
	u32 op;			/* CCP_OP_ENCRYPT or CCP_OP_DECRYPT */
};

struct ccp_cmd_poly {
	u64 rkey;		/* datastore reference for the r key */
	u64 skey;		/* datastore reference for the s key */
	u32 rkeylen;		/* always 16 */
	u32 skeylen;		/* always 16 */
};

struct ccp_cmd_aead {
	u64 key;		/* datastore reference for the key */
	u64 ctrnonce;		/* DMA address of the 16-byte counter+nonce */
	u32 keylen;		/* key length: 32 bytes */
	u32 ctrnoncelen;	/* always 16 */
	u32 op;			/* CCP_OP_ENCRYPT or CCP_OP_DECRYPT */
};

struct ccp_cmd_aad_update {
	u64 aad;		/* DMA address of AAD data */
	u32 aadlen;		/* AAD length (must be multiple of 16) */
};

struct ccp_cmd_aad_final {
	u64 aad;		/* DMA address of last AAD data */
	u32 aadlen;		/* last AAD length (any size) */
};

struct ccp_cmd_update {
	u64 input;		/* DMA address of input data */
	u64 output;		/* DMA address of output data */
	u32 iolen;		/* input/output length */
};

struct ccp_cmd_final {
	u64 input;		/* DMA address of last input data */
	u64 output;		/* DMA address of last output data */
	u64 tag;		/* DMA address of the 16-byte tag */
	u32 iolen;		/* last input/output data length */
	u32 taglen;		/* tag length (always 16) */
};

/* CCP Command Union */

union ccp_cmd {
	struct ccp_cmd_chacha	cmd_chacha;
	struct ccp_cmd_poly	cmd_poly;
	struct ccp_cmd_aead	cmd_aead;
	struct ccp_cmd_aad_update cmd_aad_update;
	struct ccp_cmd_aad_final cmd_aad_final;
	struct ccp_cmd_update	cmd_update;
	struct ccp_cmd_final	cmd_final;
};

#endif /* CMH_CCP_ABI_H */
