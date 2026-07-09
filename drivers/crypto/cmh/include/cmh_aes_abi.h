/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- AES Core ABI Definitions
 *
 * Kernel-side definitions for the CMH AES ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_AES_ABI_H
#define CMH_AES_ABI_H

#include <linux/types.h>

/* AES Block Size */

#define CMH_AES_BLOCK_SIZE	16U
#define CMH_AES_IV_SIZE		16U

/* AES Modes (per CMH AES ABI) */

#define AES_MODE_ECB		1U
#define AES_MODE_CBC		2U
#define AES_MODE_CTR		3U
#define AES_MODE_CFB		4U
#define AES_MODE_GCM		5U
#define AES_MODE_CMAC		6U
#define AES_MODE_CCM		7U
#define AES_MODE_XTS		8U

/* AES Operations (per CMH AES ABI) */

#define AES_OP_DECRYPT		1U
#define AES_OP_ENCRYPT		2U

/* AES Command IDs */

#define AES_CMD_INIT		0x01U
#define AES_CMD_AAD_UPDATE	0x02U
#define AES_CMD_AAD_FINAL	0x03U
#define AES_CMD_UPDATE		0x04U
#define AES_CMD_FINAL		0x05U
#define AES_CMD_SCATTERGATHER	0x06U
#define AES_CMD_CCM_INIT	0x0AU
#define AES_CMD_AAD_FINAL_AUTH	0x0EU

/* AES Command Structures */

struct aes_cmd_init {
	u64 key;	/* datastore reference for the key */
	u64 iv;		/* DMA address of the IV (or nonce in CCM) */
	u32 keylen;	/* key length in bytes */
	u32 ivlen;	/* IV length in bytes (0..16) */
	u32 mode;	/* AES mode (AES_MODE_*) */
	u32 op;		/* AES operation (AES_OP_*) */
	u32 aadlen;	/* AAD length or 0 */
	u32 iolen;	/* plaintext/ciphertext length */
	u32 taglen;	/* tag length or 0 */
	u32 xts_offset;	/* XTS block index j; 0 for the skcipher path */
};

struct aes_cmd_aad_final {
	u64 data;	/* DMA address of AAD data */
	u32 datalen;	/* AAD data length */
};

struct aes_cmd_aad_final_auth {
	u64 data;	/* DMA address of final AAD data */
	u32 datalen;	/* final AAD data length */
	u64 tag;		/* DMA address of tag */
	u32 taglen;	/* tag length */
};

struct aes_cmd_update {
	u64 input;	/* DMA address of input data */
	u64 output;	/* DMA address of output data */
	u32 iolen;	/* input/output data length */
};

struct aes_cmd_final {
	u64 input;	/* DMA address of last input data */
	u64 output;	/* DMA address of last output data */
	u64 tag;	/* DMA address of tag (AEAD only) */
	u32 iolen;	/* last input/output data length */
	u32 taglen;	/* tag length (AEAD only) */
};

/* AES Command Union */

union aes_cmd {
	struct aes_cmd_init		cmd_init;
	struct aes_cmd_update		cmd_update;
	struct aes_cmd_final		cmd_final;
	struct aes_cmd_aad_final	cmd_aad_final;
	struct aes_cmd_aad_final_auth	cmd_aad_final_auth;
};

#endif /* CMH_AES_ABI_H */
