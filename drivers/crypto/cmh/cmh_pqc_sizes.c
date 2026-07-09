// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- PQC Algorithm Size Tables
 *
 * Centralised ML-DSA and SLH-DSA parameter-size arrays.  Declared
 * extern in cmh_qse_abi.h / cmh_hcq_abi.h, defined here once to
 * avoid per-TU duplication.
 */

#include <linux/build_bug.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "cmh_qse_abi.h"
#include "cmh_hcq_abi.h"

/* ML-DSA size tables (indexed by ml_dsa_mode_idx()) */
const u32 ml_dsa_pk_size[3]  = { 1312U, 1952U, 2592U };
const u32 ml_dsa_sk_size[3]  = { 2560U, 4032U, 4896U };
const u32 ml_dsa_sk_size_masked[3] = { 3360U, 5472U, 6368U };
const u32 ml_dsa_sig_size[3] = { 2420U, 3309U, 4627U };

static_assert(ARRAY_SIZE(ml_dsa_pk_size) == ARRAY_SIZE(ml_dsa_sk_size));
static_assert(ARRAY_SIZE(ml_dsa_pk_size) == ARRAY_SIZE(ml_dsa_sk_size_masked));
static_assert(ARRAY_SIZE(ml_dsa_pk_size) == ARRAY_SIZE(ml_dsa_sig_size));

/* SLH-DSA n-values and signature sizes (indexed by param_set - 1) */
const u32 slhdsa_n[12] = {
	16, 16, 24, 24, 32, 32,		/* SHAKE 128s/f, 192s/f, 256s/f */
	16, 16, 24, 24, 32, 32,		/* SHA2 128s/f, 192s/f, 256s/f */
};

const u32 slhdsa_sig_size[12] = {
	7856,  17088, 16224, 35664, 29792, 49856,	/* SHAKE */
	7856,  17088, 16224, 35664, 29792, 49856,	/* SHA2 */
};

static_assert(ARRAY_SIZE(slhdsa_n) == ARRAY_SIZE(slhdsa_sig_size));
