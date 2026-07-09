/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- QSE Core ABI Definitions
 *
 * Kernel-side definitions for the CMH QSE ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_QSE_ABI_H
#define CMH_QSE_ABI_H

#include <linux/bits.h>
#include <linux/compiler_attributes.h>
#include <linux/types.h>

/* VCQ layout: header + [SYS_NEW] + QSE_CMD + flush */
#define QSE_VCQ_CMDS_MIN	3	/* header + cmd + flush */
#define QSE_VCQ_CMDS_MAX	4	/* header + sys_new + cmd + flush */

/* QSE Flags */
#define QSE_FLAG_USE_REF	BIT(0)
#define QSE_FLAG_USE_RNG	BIT(1)

/* QSE Command IDs */
#define QSE_CMD_ML_KEM_KEYGEN		0x01U
#define QSE_CMD_ML_KEM_ENC		0x02U
#define QSE_CMD_ML_KEM_DEC		0x03U
#define QSE_CMD_ML_DSA_KEYGEN		0x04U
#define QSE_CMD_ML_DSA_SIGN		0x05U
#define QSE_CMD_ML_DSA_VERIFY		0x06U
#define QSE_CMD_ML_KEM_KEYGEN_MASKED	0x07U
#define QSE_CMD_ML_KEM_ENC_MASKED	0x08U
#define QSE_CMD_ML_KEM_DEC_MASKED	0x09U
#define QSE_CMD_ML_DSA_KEYGEN_MASKED	0x0AU
#define QSE_CMD_ML_DSA_SIGN_MASKED	0x0BU

/* ML-KEM category values */
#define ML_KEM_K_512		2U
#define ML_KEM_K_768		3U
#define ML_KEM_K_1024		4U

/* ML-DSA mode values */
#define ML_DSA_MODE_44		2U
#define ML_DSA_MODE_65		3U
#define ML_DSA_MODE_87		5U

/* ML-DSA special message length for externalMu (pre-hashed 64-byte input) */
#define ML_DSA_MLEN_EXTERNAL_MU	0xFFFFFFFFU
#define ML_DSA_EXTMU_LEN	64U	/* actual copy size for externalMu */

/* ML-DSA maximum message length */
#define ML_DSA_MAX_MLEN		10240U

/* Shared secret size */
#define ML_KEM_SS_LEN		32U
#define ML_KEM_SS_LEN_MASKED	64U

/* Seed sizes */
#define QSE_SEED_LEN		32U
#define QSE_SEED_LEN_MASKED	64U

/*
 * ML-KEM size tables -- indexed by (k - 2).
 *  [0] = ML-KEM-512 (k=2)
 *  [1] = ML-KEM-768 (k=3)
 *  [2] = ML-KEM-1024 (k=4)
 */
#define ML_KEM_LEVELS		3U

#define ML_KEM_EK_SIZE(k)	(384U * (k) + 32U)
#define ML_KEM_DK_SIZE(k)	(768U * (k) + 96U)
#define ML_KEM_DK_SIZE_MASKED(k) (1152U * (k) + 128U)

static inline u32 ml_kem_ct_size(u32 k)
{
	u32 du = (k == 4U) ? 11U : 10U;
	u32 dv = (k == 4U) ? 5U : 4U;

	return 32U * (k * du + dv);
}

#define ML_KEM_CT_SIZE(k)	ml_kem_ct_size(k)

/*
 * ML-DSA size tables -- indexed by mode.
 * Mode values: 2 (ML-DSA-44), 3 (ML-DSA-65), 5 (ML-DSA-87).
 */
extern const u32 ml_dsa_pk_size[];
extern const u32 ml_dsa_sk_size[];
extern const u32 ml_dsa_sk_size_masked[];
extern const u32 ml_dsa_sig_size[];

/* Map ML-DSA mode (2/3/5) -> table index (0/1/2) */
static inline int ml_dsa_mode_idx(u32 mode)
{
	switch (mode) {
	case 2: return 0;
	case 3: return 1;
	case 5: return 2;
	default: return -1;
	}
}

/* Map ML-KEM k (2/3/4) -> table index (0/1/2), or -1 if invalid */
static inline int ml_kem_k_idx(u32 k)
{
	if (k >= 2U && k <= 4U)
		return (int)(k - 2U);
	return -1;
}

/* QSE Command Structures -- match CMH eSW ABI exactly */

struct qse_cmd_ml_kem_keygen {
	u32 k;
	u32 flags;
	u64 seed;
	u64 z;
	u64 ek;
	u64 dk;
	u32 dk_type;
};

struct qse_cmd_ml_kem_enc {
	u32 k;
	u32 flags;
	u64 coin;
	u64 ek;
	u64 ct;
	u64 ss;
	u32 ss_type;
};

struct qse_cmd_ml_kem_dec {
	u32 k;
	u32 flags;
	u64 ct;
	u64 dk;
	u64 ss;
	u32 ss_type;
};

struct qse_cmd_ml_dsa_keygen {
	u32 mode;
	u32 flags;
	u64 seed;
	u64 pk;
	u64 sk;
	u32 sk_type;
};

struct qse_cmd_ml_dsa_sign {
	u32 mode;
	u32 flags;
	u64 rnd;
	u64 m;
	u64 sk;
	u64 sig;
	u32 mlen;
};

struct qse_cmd_ml_dsa_verify {
	u32 mode;
	u32 flags;
	u64 m;
	u64 pk;
	u64 sig;
	u32 mlen;
};

union qse_cmd {
	struct qse_cmd_ml_kem_keygen cmd_ml_kem_keygen;
	struct qse_cmd_ml_kem_enc    cmd_ml_kem_enc;
	struct qse_cmd_ml_kem_dec    cmd_ml_kem_dec;
	struct qse_cmd_ml_dsa_keygen cmd_ml_dsa_keygen;
	struct qse_cmd_ml_dsa_sign   cmd_ml_dsa_sign;
	struct qse_cmd_ml_dsa_verify cmd_ml_dsa_verify;
};

#endif /* CMH_QSE_ABI_H */
