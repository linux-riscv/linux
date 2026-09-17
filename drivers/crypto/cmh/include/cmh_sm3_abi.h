/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM3 Hash Core ABI Definitions
 *
 * Kernel-side definitions for the CMH SM3 ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_SM3_ABI_H
#define CMH_SM3_ABI_H

#include <linux/types.h>

/* SM3 Commands */

#define SM3_CMD_INIT            0x01U
#define SM3_CMD_UPDATE          0x02U
#define SM3_CMD_FINAL           0x03U
#define SM3_CMD_UPDATE2D        0x04U
#define SM3_CMD_GATHER          0x06U
#define SM3_CMD_SAVE            0x07U
#define SM3_CMD_RESTORE         0x08U

/* SM3 Digest / Block Sizes */

#define CMH_SM3_DIGEST_SIZE     32U
#define CMH_SM3_BLOCK_SIZE      64U

/* SM3 Context (for SAVE/RESTORE) */

#define SM3_CONTEXT_WORDS       29U
#define SM3_CONTEXT_SIZE        (SM3_CONTEXT_WORDS * 4 + 4)  /* ctx[29] + crc */

/* SM3 Command Structures */

struct sm3_cmd_update {
	u64 input;      /* DMA physical address of input data */
	u32 inlen;      /* input data length in bytes */
};

struct sm3_cmd_final {
	u64 digest;     /* DMA physical address for output digest */
	u32 outlen;     /* digest length in bytes */
};

struct sm3_cmd_update2d {
	u64 input;      /* DMA source address for input data */
	u64 output;     /* DMA destination address for pass-through data */
	u32 iolen;      /* input/pass-through data length in bytes */
};

struct sm3_cmd_gather {
	u64 lista;      /* DMA address of dma_scattergather_item chain */
	u32 sgcmd;      /* SM3 sub-command: SM3_CMD_UPDATE or SM3_CMD_UPDATE2D */
};

struct sm3_cmd_save {
	u64 output;     /* DMA physical address for saved context */
	u32 outlen;     /* must be SM3_CONTEXT_SIZE */
};

struct sm3_cmd_restore {
	u64 input;      /* DMA physical address of saved context */
	u32 inlen;      /* must be SM3_CONTEXT_SIZE */
};

/* SM3 Command Union */

union sm3_cmd {
	struct sm3_cmd_update   cmd_update;
	struct sm3_cmd_final    cmd_final;
	struct sm3_cmd_update2d cmd_update2d;
	struct sm3_cmd_gather   cmd_gather;
	struct sm3_cmd_save     cmd_save;
	struct sm3_cmd_restore  cmd_restore;
};

#endif /* CMH_SM3_ABI_H */
