/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM4 Core ABI Definitions
 *
 * Kernel-side definitions for the CMH SM4 ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_SM4_ABI_H
#define CMH_SM4_ABI_H

#include <linux/types.h>

/* SM4 Block Size */

#define CMH_SM4_BLOCK_SIZE	16U
#define CMH_SM4_IV_SIZE		16U
#define CMH_SM4_KEY_SIZE	16U	/* SM4 always uses 128-bit keys */

/* SM4 Modes (per CMH SM4 ABI) */

#define SM4_MODE_ECB		1U
#define SM4_MODE_CBC		2U
#define SM4_MODE_CTR		3U
#define SM4_MODE_CFB		5U
#define SM4_MODE_GCM		6U
#define SM4_MODE_CMAC		7U
#define SM4_MODE_CCM		8U
#define SM4_MODE_XTS		9U
#define SM4_MODE_XCBC		10U

/* SM4 Operations (per CMH SM4 ABI) */

#define SM4_OP_DECRYPT		1U
#define SM4_OP_ENCRYPT		2U

/* SM4 Command IDs */

#define SM4_CMD_INIT		0x01U
#define SM4_CMD_AAD_UPDATE	0x02U
#define SM4_CMD_AAD_FINAL	0x03U
#define SM4_CMD_UPDATE		0x04U
#define SM4_CMD_FINAL		0x05U
#define SM4_CMD_SCATTERGATHER	0x06U
#define SM4_CMD_CCM_INIT	0x09U

/* SM4 Command Structures */

struct sm4_cmd_init {
	u64 key;	/* datastore reference for the key */
	u64 iv;		/* DMA address of the IV */
	u32 keylen;	/* key length in bytes (16, or 32 for XTS) */
	u32 ivlen;	/* IV length in bytes (0..16) */
	u32 mode;	/* SM4 mode (SM4_MODE_*) */
	u32 op;		/* SM4 operation (SM4_OP_*) */
	u32 aadlen;	/* AAD length or 0 */
	u32 iolen;	/* plaintext/ciphertext length */
};

struct sm4_cmd_update {
	u64 input;	/* DMA address of input data */
	u64 output;	/* DMA address of output data */
	u32 iolen;	/* input/output data length */
};

struct sm4_cmd_final {
	u64 input;	/* DMA address of last input data */
	u64 output;	/* DMA address of last output data */
	u64 tag;	/* DMA address of tag (AEAD only) */
	u32 iolen;	/* last input/output data length */
	u32 taglen;	/* tag length (AEAD only) */
};

struct sm4_cmd_aad_final {
	u64 data;	/* DMA address of AAD data */
	u32 datalen;	/* AAD data length */
};

struct sm4_cmd_ccm_init {
	u64 key;	/* datastore reference for the key */
	u64 nonce;	/* DMA address of the nonce */
	u32 keylen;	/* key length in bytes (always 16) */
	u32 noncelen;	/* nonce length (15 - L) */
	u32 op;		/* SM4 operation (SM4_OP_*) */
	u32 aadlen;	/* AAD length */
	u32 iolen;	/* plaintext/ciphertext length */
	u32 taglen;	/* tag length */
};

/* SM4 Command Union */

union sm4_cmd {
	struct sm4_cmd_init	cmd_init;
	struct sm4_cmd_update	cmd_update;
	struct sm4_cmd_final	cmd_final;
	struct sm4_cmd_aad_final cmd_aad_final;
	struct sm4_cmd_ccm_init	cmd_ccm_init;
};

#endif /* CMH_SM4_ABI_H */
