/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- HCQ Core ABI Definitions
 *
 * Kernel-side definitions for the CMH HCQ ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_HCQ_ABI_H
#define CMH_HCQ_ABI_H

#include <linux/compiler_attributes.h>
#include <linux/types.h>

/* VCQ layout: header + [SYS cmds] + HCQ_CMD + [sys_read] + flush */
#define HCQ_VCQ_CMDS_MIN	3	/* header + cmd + flush */
#define HCQ_VCQ_CMDS_MAX	6	/* keygen: hdr+new+write+cmd+read+flush */

/* HCQ Command IDs */
#define HCQ_CMD_XMSS_VERIFY			0x03U
#define HCQ_CMD_LMS_VERIFY			0x04U
#define HCQ_CMD_SLHDSA_VERIFY_INTERNAL		0x05U
#define HCQ_CMD_SLHDSA_VERIFY			0x06U
#define HCQ_CMD_SLHDSA_VERIFY_PREHASH		0x07U
#define HCQ_CMD_SLHDSA_VERIFY_PREHASH_DIGEST	0x08U
#define HCQ_CMD_SLHDSA_KEYGEN			0x09U
#define HCQ_CMD_SLHDSA_SIGN_INTERNAL		0x10U
#define HCQ_CMD_SLHDSA_SIGN			0x11U
#define HCQ_CMD_SLHDSA_SIGN_PREHASH		0x12U
#define HCQ_CMD_SLHDSA_SIGN_PREHASH_DIGEST	0x13U
#define HCQ_CMD_SLHDSA_PUBGEN			0x14U

/* SLH-DSA Parameter Set IDs */
#define HCQ_SLHDSA_SHAKE_128S	1U
#define HCQ_SLHDSA_SHAKE_128F	2U
#define HCQ_SLHDSA_SHAKE_192S	3U
#define HCQ_SLHDSA_SHAKE_192F	4U
#define HCQ_SLHDSA_SHAKE_256S	5U
#define HCQ_SLHDSA_SHAKE_256F	6U
#define HCQ_SLHDSA_SHA2_128S	7U
#define HCQ_SLHDSA_SHA2_128F	8U
#define HCQ_SLHDSA_SHA2_192S	9U
#define HCQ_SLHDSA_SHA2_192F	10U
#define HCQ_SLHDSA_SHA2_256S	11U
#define HCQ_SLHDSA_SHA2_256F	12U
#define HCQ_SLHDSA_PARAM_MAX	12U

/* SLH-DSA Prehash Algorithm IDs */
#define HCQ_SLHDSA_PREHASH_SHA256	1U
#define HCQ_SLHDSA_PREHASH_SHA512	2U
#define HCQ_SLHDSA_PREHASH_SHAKE128	3U
#define HCQ_SLHDSA_PREHASH_SHAKE256	4U

/* SLH-DSA size limits */
#define SLHDSA_MAX_PK_SIZE	64U	/* 2*n, n=32 */
#define SLHDSA_MAX_SK_SIZE	128U	/* 4*n, n=32 */
#define SLHDSA_MAX_SEED_SIZE	96U	/* 3*n, n=32 */
#define SLHDSA_MAX_SIG_SIZE	49856U	/* SHAKE-256f / SHA2-256f */
#define SLHDSA_MAX_MSG_LEN	128U
#define SLHDSA_MAX_CTX_LEN	255U

/* LMS/HSS size limits -- derived from eSW HCQ ABI constraints */
#define LMS_MAX_PK_LEN		60U	/* eSW public-key buffer */
#define LMS_MAX_MSG_LEN		256U	/* SHS_LMS_MESSAGE_LEN_MAX */
#define LMS_MAX_SIG_LEN		13364U	/* eSW signature buffer */

/* XMSS/XMSS-MT size limits -- derived from eSW HCQ ABI constraints */
#define XMSS_MAX_PK_LEN	136U	/* eSW public-key buffer */
#define XMSS_MAX_MSG_LEN	64U	/* SHS_XMSS_MESSAGE_LEN_MAX */
#define XMSS_MAX_SIG_LEN	27688U	/* eSW signature buffer */

/* SLH-DSA n-value for each parameter set (index = param_set - 1) */
extern const u32 slhdsa_n[];

/* SLH-DSA signature sizes (index = param_set - 1) */
extern const u32 slhdsa_sig_size[];

/* Derive PK/SK/seed sizes from n */
static inline u32 slhdsa_pk_size(u32 param_set)
{
	if (param_set < 1U || param_set > HCQ_SLHDSA_PARAM_MAX)
		return 0;
	return 2U * slhdsa_n[param_set - 1U];
}

static inline u32 slhdsa_sk_size(u32 param_set)
{
	if (param_set < 1U || param_set > HCQ_SLHDSA_PARAM_MAX)
		return 0;
	return 4U * slhdsa_n[param_set - 1U];
}

static inline u32 slhdsa_seed_size(u32 param_set)
{
	if (param_set < 1U || param_set > HCQ_SLHDSA_PARAM_MAX)
		return 0;
	return 3U * slhdsa_n[param_set - 1U];
}

static inline u32 slhdsa_get_sig_size(u32 param_set)
{
	if (param_set < 1U || param_set > HCQ_SLHDSA_PARAM_MAX)
		return 0;
	return slhdsa_sig_size[param_set - 1U];
}

/* HCQ Command Structures -- match CMH eSW ABI exactly */

struct hcq_cmd_xmss_verify {
	u32 xmss_mt;	/* 0 = XMSS, 1 = XMSS-MT */
	u32 pk_len;
	u32 sig_len;
	u32 dig_len;
	u64 pk;
	u64 sig;
	u64 dig;
};

struct hcq_cmd_lms_verify {
	u32 lms_hss;	/* 0 = LMS, 1 = LMS-HSS */
	u32 pk_len;
	u32 sig_len;
	u32 dig_len;
	u64 pk;
	u64 sig;
	u64 dig;
};

struct hcq_cmd_slhdsa_verify_internal {
	u32 parameter_set;
	u32 message_len;
	u64 message;
	u64 pk;
	u64 sig;
};

struct hcq_cmd_slhdsa_verify {
	u32 parameter_set;
	u32 message_len;
	u64 message;
	u64 context;
	u64 pk;
	u64 sig;
	u32 context_len;
};

struct hcq_cmd_slhdsa_verify_prehash {
	u32 parameter_set;
	u32 prehash_algo;
	u32 message_len;
	u32 context_len;
	u64 message;
	u64 context;
	u64 pk;
	u64 sig;
};

struct hcq_cmd_slhdsa_keygen {
	u32 parameter_set;
	u32 seed_len;
	u32 pk_len;
	u32 sk_len;
	u64 seed;	/* DS reference */
	u64 pk;		/* extmem addr */
	u64 sk;		/* DS reference */
};

struct hcq_cmd_slhdsa_sign_internal {
	u32 parameter_set;
	u32 message_len;
	u64 add_random;	/* extmem addr, 0 = none */
	u64 message;
	u64 sk;		/* DS reference */
	u64 sig;	/* extmem addr */
};

struct hcq_cmd_slhdsa_sign {
	u32 parameter_set;
	u32 message_len;
	u64 add_random;
	u64 message;
	u64 context;
	u64 sk;		/* DS reference */
	u64 sig;	/* extmem addr */
	u32 context_len;
};

struct hcq_cmd_slhdsa_sign_prehash {
	u32 parameter_set;
	u32 prehash_algo;
	u32 message_len;
	u32 context_len;
	u64 add_random;
	u64 message;
	u64 context;
	u64 sk;		/* DS reference */
	u64 sig;	/* extmem addr */
};

struct hcq_cmd_slhdsa_pubgen {
	u32 parameter_set;
	u32 sk_len;
	u64 sk;		/* DS reference */
	u64 pk;		/* extmem addr */
};

union hcq_cmd {
	struct hcq_cmd_xmss_verify		cmd_xmss_verify;
	struct hcq_cmd_lms_verify		cmd_lms_verify;
	struct hcq_cmd_slhdsa_verify_internal	cmd_slhdsa_verify_internal;
	struct hcq_cmd_slhdsa_verify		cmd_slhdsa_verify;
	struct hcq_cmd_slhdsa_verify_prehash	cmd_slhdsa_verify_prehash;
	struct hcq_cmd_slhdsa_keygen		cmd_slhdsa_keygen;
	struct hcq_cmd_slhdsa_sign_internal	cmd_slhdsa_sign_internal;
	struct hcq_cmd_slhdsa_sign		cmd_slhdsa_sign;
	struct hcq_cmd_slhdsa_sign_prehash	cmd_slhdsa_sign_prehash;
	struct hcq_cmd_slhdsa_pubgen		cmd_slhdsa_pubgen;
};

#endif /* CMH_HCQ_ABI_H */
