/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- DRBG Core ABI Definitions
 *
 * Kernel-side definitions for the CMH DRBG ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_DRBG_ABI_H
#define CMH_DRBG_ABI_H

#include <linux/types.h>

/* DRBG Commands */

#define DRBG_CMD_CONFIG         0x01U
#define DRBG_CMD_GENERATE       0x02U
#define DRBG_CMD_DATASTORE      0x03U
#define DRBG_CMD_RESET          0x04U

/* DRBG Entropy Ratio (per CMH DRBG ABI) */

#define DRBG_ENTROPY_RATIO_ONE          0U
#define DRBG_ENTROPY_RATIO_ONE_HALF     1U
#define DRBG_ENTROPY_RATIO_ONE_THIRD    2U
#define DRBG_ENTROPY_RATIO_ONE_FOURTH   3U

/* DRBG Security Strength (per CMH DRBG ABI) */

#define DRBG_SECURITY_STRENGTH_128      0x00U
#define DRBG_SECURITY_STRENGTH_256      0x10U

/* DRBG Personalization Data Length */

#define DRBG_PADATA_LEN         16U

/* DRBG Command Structures */

struct drbg_cmd_config {
	u32 entropy_ratio;      /* drbg_entropy_ratio value */
	u32 security_strength;  /* drbg_security_strength value */
	u8  padata[DRBG_PADATA_LEN];
};

struct drbg_cmd_generate {
	u64 dst;                /* DMA physical address for output */
	u32 len;                /* requested output length in bytes */
	u8  padata[DRBG_PADATA_LEN];
};

struct drbg_cmd_datastore {
	u64 ref;                /* datastore reference */
	u32 len;                /* data length in bytes */
	u32 type;               /* datastore type */
	u8  padata[DRBG_PADATA_LEN];
};

/* DRBG Command Union */

union drbg_cmd {
	struct drbg_cmd_config    cmd_config;
	struct drbg_cmd_generate  cmd_generate;
	struct drbg_cmd_datastore cmd_datastore;
};

#endif /* CMH_DRBG_ABI_H */
