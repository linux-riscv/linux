/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Hash Core (HC) ABI Definitions
 *
 * Kernel-side definitions for the CMH HC (Hash Core) ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_HC_ABI_H
#define CMH_HC_ABI_H

#include <linux/bits.h>
#include <linux/types.h>

/* HC Commands */

#define HC_CMD_INIT             0x01U
#define HC_CMD_HMAC             0x02U
#define HC_CMD_UPDATE           0x03U
#define HC_CMD_FINAL            0x04U
#define HC_CMD_UPDATE2D         0x05U
#define HC_CMD_SQUEEZE          0x07U
#define HC_CMD_GATHER           0x08U
#define HC_CMD_CSHAKE           0x09U
#define HC_CMD_KMAC             0x0AU
#define HC_CMD_SAVE             0x0BU
#define HC_CMD_RESTORE          0x0CU

/* HC Algorithms (per CMH HC ABI) */

#define HC_ALGO_SHA2_224        1U
#define HC_ALGO_SHA2_256        2U
#define HC_ALGO_SHA2_384        3U
#define HC_ALGO_SHA2_512        4U
#define HC_ALGO_SHA3_224        5U
#define HC_ALGO_SHA3_256        6U
#define HC_ALGO_SHA3_384        7U
#define HC_ALGO_SHA3_512        8U
#define HC_ALGO_SHAKE128        9U
#define HC_ALGO_SHAKE256        10U

/* HC Algo Flags */

#define HC_ALGO_FLAG_SCA_KEY    BIT(18)      /* SCA key in 2 shares */
#define HC_ALGO_FLAG_SCA_OUT    BIT(19)      /* SCA output in 2 shares */

#define HC_ALGO_SET(flags, algo)  (((flags) & 0xFF0000UL) | ((algo) & 0xFFUL))
#define HC_ALGO_GET(algo)         ((algo) & 0xFFU)

/* Hash Digest Sizes */

#define CMH_SHA224_DIGEST_SIZE  28U
#define CMH_SHA256_DIGEST_SIZE  32U
#define CMH_SHA384_DIGEST_SIZE  48U
#define CMH_SHA512_DIGEST_SIZE  64U

/* SHA-3 digest sizes are the same as SHA-2 for matching output widths */
#define CMH_SHA3_224_DIGEST_SIZE  28U
#define CMH_SHA3_256_DIGEST_SIZE  32U
#define CMH_SHA3_384_DIGEST_SIZE  48U
#define CMH_SHA3_512_DIGEST_SIZE  64U

/* SHAKE default output lengths (fixed-output ahash registration) */
#define CMH_SHAKE128_DIGEST_SIZE  32U   /* 128-bit security -> 32 bytes */
#define CMH_SHAKE256_DIGEST_SIZE  64U   /* 256-bit security -> 64 bytes */

/* HC Context (for SAVE/RESTORE) */

#define HC_CONTEXT_WORDS        149U
#define HC_CONTEXT_SIZE         (HC_CONTEXT_WORDS * 4 + 4)  /* ctx[149] + crc */

/* cSHAKE function name max length */

#define HC_CSHAKE_MAX_NAMELEN   36U

/*
 * Maximum customization string (S) length for cSHAKE / KMAC.
 *
 * S is packed as inline VCQ data after the CSHAKE/KMAC command slot.
 * The worst-case VCQ layout (KMAC with raw key + GATHER) uses 5 fixed
 * slots out of CMH_KMAC_MAX_PAYLOAD (9), leaving 4 inline slots.
 * Each VCQ slot is 64 bytes, so the safe limit is 4 * 64 = 256 bytes.
 */
#define HC_CSHAKE_MAX_CUSTOMLEN 256U

/* HC Command Structures */

struct hc_cmd_init {
	u32 algo;       /* hc_algo value, optionally ORed with HC_ALGO_FLAG_* */
};

struct hc_cmd_hmac {
	u64 key;        /* datastore reference for HMAC key */
	u32 keylen;     /* key length in bytes */
	u32 algo;       /* hc_algo value */
};

struct hc_cmd_update {
	u64 input;      /* DMA physical address of input data */
	u32 inlen;      /* input data length in bytes */
};

struct hc_cmd_final {
	u64 digest;     /* DMA physical address for output digest */
	u32 outlen;     /* digest length in bytes */
};

struct hc_cmd_update2d {
	u64 input;      /* DMA source address for input data */
	u64 output;     /* DMA destination address for pass-through data */
	u32 iolen;      /* input/pass-through data length in bytes */
};

struct hc_cmd_gather {
	u64 lista;      /* DMA address of dma_scattergather_item chain */
	u32 sgcmd;      /* HC sub-command: HC_CMD_UPDATE or HC_CMD_UPDATE2D */
};

struct hc_cmd_cshake {
	u64 custom;     /* DMA address for the customization string */
	u32 customlen;  /* length of the customization string */
	u32 algo;       /* HC_ALGO_SHAKE128 or HC_ALGO_SHAKE256 */
	u32 namelen;    /* length of the function name string */
	u8  name[HC_CSHAKE_MAX_NAMELEN]; /* function name string (inline) */
};

struct hc_cmd_kmac {
	u64 key;        /* datastore reference for KMAC key */
	u64 custom;     /* DMA address for the customization string */
	u32 keylen;     /* key length in bytes */
	u32 customlen;  /* length of the customization string */
	u32 algo;       /* HC_ALGO_SHAKE128 or HC_ALGO_SHAKE256 */
	u32 outlen;     /* requested output digest length */
};

struct hc_cmd_save {
	u64 output;     /* DMA physical address for saved context */
	u32 outlen;     /* must be HC_CONTEXT_SIZE */
};

struct hc_cmd_restore {
	u64 input;      /* DMA physical address of saved context */
	u32 inlen;      /* must be HC_CONTEXT_SIZE */
};

/* HC Command Union */

union hc_cmd {
	struct hc_cmd_init      cmd_init;
	struct hc_cmd_hmac      cmd_hmac;
	struct hc_cmd_cshake    cmd_cshake;
	struct hc_cmd_kmac      cmd_kmac;
	struct hc_cmd_update    cmd_update;
	struct hc_cmd_final     cmd_final;
	struct hc_cmd_update2d  cmd_update2d;
	struct hc_cmd_gather    cmd_gather;
	struct hc_cmd_save      cmd_save;
	struct hc_cmd_restore   cmd_restore;
};

#endif /* CMH_HC_ABI_H */
