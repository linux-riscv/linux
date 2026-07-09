// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- HCQ Core VCQ Builders
 *
 * VCQ builder functions for SLH-DSA, LMS, and XMSS commands.
 * Each function populates a single vcq_cmd slot.  Callers assemble
 * complete VCQs with header + command(s) + flush, then submit via
 * cmh_tm_submit_sync().
 */

#include <linux/string.h>

#include "cmh_sys.h"

/* -- HCQ flush -- */

/**
 * vcq_add_hcq_flush() - Build an HCQ flush VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 */
void vcq_add_hcq_flush(struct vcq_cmd *slot, u32 core_id)
{
	vcq_add_flush(slot, core_id);
}

/* -- SLH-DSA -- */

/**
 * vcq_add_hcq_slhdsa_keygen() - Build an SLH-DSA key generation VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @param_set: SLH-DSA parameter set identifier
 * @seed_len: Length of seed buffer in bytes
 * @pk_len: Length of public key buffer in bytes
 * @sk_len: Length of secret key buffer in bytes
 * @seed: DMA address of seed input buffer
 * @pk: DMA address of public key output buffer
 * @sk: DMA address of secret key output buffer
 */
void vcq_add_hcq_slhdsa_keygen(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			       u32 seed_len, u32 pk_len, u32 sk_len,
			       u64 seed, u64 pk, u64 sk)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_SLHDSA_KEYGEN);
	slot->hwc.hcq.cmd_slhdsa_keygen.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_keygen.seed_len = seed_len;
	slot->hwc.hcq.cmd_slhdsa_keygen.pk_len = pk_len;
	slot->hwc.hcq.cmd_slhdsa_keygen.sk_len = sk_len;
	slot->hwc.hcq.cmd_slhdsa_keygen.seed = seed;
	slot->hwc.hcq.cmd_slhdsa_keygen.pk = pk;
	slot->hwc.hcq.cmd_slhdsa_keygen.sk = sk;
}

/**
 * vcq_add_hcq_slhdsa_sign() - Build an SLH-DSA signing VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @param_set: SLH-DSA parameter set identifier
 * @msg_len: Length of message buffer in bytes
 * @ctx_len: Length of context string in bytes
 * @add_random: DMA address of additional randomness buffer
 * @msg: DMA address of message buffer
 * @ctx: DMA address of context string buffer
 * @sk: DMA address of secret key buffer
 * @sig: DMA address of signature output buffer
 */
void vcq_add_hcq_slhdsa_sign(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			     u32 msg_len, u32 ctx_len,
			     u64 add_random, u64 msg, u64 ctx,
			     u64 sk, u64 sig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_SLHDSA_SIGN);
	slot->hwc.hcq.cmd_slhdsa_sign.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_sign.message_len = msg_len;
	slot->hwc.hcq.cmd_slhdsa_sign.add_random = add_random;
	slot->hwc.hcq.cmd_slhdsa_sign.message = msg;
	slot->hwc.hcq.cmd_slhdsa_sign.context = ctx;
	slot->hwc.hcq.cmd_slhdsa_sign.sk = sk;
	slot->hwc.hcq.cmd_slhdsa_sign.sig = sig;
	slot->hwc.hcq.cmd_slhdsa_sign.context_len = ctx_len;
}

/**
 * vcq_add_hcq_slhdsa_sign_internal() - Build an SLH-DSA internal signing VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @param_set: SLH-DSA parameter set identifier
 * @msg_len: Length of message buffer in bytes
 * @add_random: DMA address of additional randomness buffer
 * @msg: DMA address of message buffer
 * @sk: DMA address of secret key buffer
 * @sig: DMA address of signature output buffer
 */
void vcq_add_hcq_slhdsa_sign_internal(struct vcq_cmd *slot, u32 core_id, u32 param_set,
				      u32 msg_len, u64 add_random,
				      u64 msg, u64 sk, u64 sig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_SLHDSA_SIGN_INTERNAL);
	slot->hwc.hcq.cmd_slhdsa_sign_internal.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_sign_internal.message_len = msg_len;
	slot->hwc.hcq.cmd_slhdsa_sign_internal.add_random = add_random;
	slot->hwc.hcq.cmd_slhdsa_sign_internal.message = msg;
	slot->hwc.hcq.cmd_slhdsa_sign_internal.sk = sk;
	slot->hwc.hcq.cmd_slhdsa_sign_internal.sig = sig;
}

/**
 * vcq_add_hcq_slhdsa_verify() - Build an SLH-DSA verification VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @param_set: SLH-DSA parameter set identifier
 * @msg_len: Length of message buffer in bytes
 * @ctx_len: Length of context string in bytes
 * @msg: DMA address of message buffer
 * @ctx: DMA address of context string buffer
 * @pk: DMA address of public key buffer
 * @sig: DMA address of signature buffer to verify
 */
void vcq_add_hcq_slhdsa_verify(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			       u32 msg_len, u32 ctx_len,
			       u64 msg, u64 ctx, u64 pk, u64 sig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_SLHDSA_VERIFY);
	slot->hwc.hcq.cmd_slhdsa_verify.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_verify.message_len = msg_len;
	slot->hwc.hcq.cmd_slhdsa_verify.message = msg;
	slot->hwc.hcq.cmd_slhdsa_verify.context = ctx;
	slot->hwc.hcq.cmd_slhdsa_verify.pk = pk;
	slot->hwc.hcq.cmd_slhdsa_verify.sig = sig;
	slot->hwc.hcq.cmd_slhdsa_verify.context_len = ctx_len;
}

/**
 * vcq_add_hcq_slhdsa_sign_prehash() - Build an SLH-DSA prehash signing VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @cmd: VCQ command ID (sign-prehash variant)
 * @param_set: SLH-DSA parameter set identifier
 * @prehash_algo: Prehash algorithm identifier
 * @msg_len: Length of message buffer in bytes
 * @ctx_len: Length of context string in bytes
 * @add_random: DMA address of additional randomness buffer
 * @msg: DMA address of message buffer
 * @ctx: DMA address of context string buffer
 * @sk: DMA address of secret key buffer
 * @sig: DMA address of signature output buffer
 */
void vcq_add_hcq_slhdsa_sign_prehash(struct vcq_cmd *slot, u32 core_id,
				     u32 cmd, u32 param_set, u32 prehash_algo,
				     u32 msg_len, u32 ctx_len,
				     u64 add_random, u64 msg, u64 ctx,
				     u64 sk, u64 sig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd);
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.prehash_algo = prehash_algo;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.message_len = msg_len;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.context_len = ctx_len;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.add_random = add_random;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.message = msg;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.context = ctx;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.sk = sk;
	slot->hwc.hcq.cmd_slhdsa_sign_prehash.sig = sig;
}

/**
 * vcq_add_hcq_slhdsa_verify_prehash() - Build an SLH-DSA prehash verify VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @cmd: VCQ command ID (verify-prehash variant)
 * @param_set: SLH-DSA parameter set identifier
 * @prehash_algo: Prehash algorithm identifier
 * @msg_len: Length of message buffer in bytes
 * @ctx_len: Length of context string in bytes
 * @msg: DMA address of message buffer
 * @ctx: DMA address of context string buffer
 * @pk: DMA address of public key buffer
 * @sig: DMA address of signature buffer to verify
 */
void vcq_add_hcq_slhdsa_verify_prehash(struct vcq_cmd *slot, u32 core_id,
				       u32 cmd, u32 param_set, u32 prehash_algo,
				       u32 msg_len, u32 ctx_len,
				       u64 msg, u64 ctx, u64 pk, u64 sig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd);
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.prehash_algo = prehash_algo;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.message_len = msg_len;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.context_len = ctx_len;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.message = msg;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.context = ctx;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.pk = pk;
	slot->hwc.hcq.cmd_slhdsa_verify_prehash.sig = sig;
}

/**
 * vcq_add_hcq_slhdsa_verify_internal() - Build an SLH-DSA internal verify VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @param_set: SLH-DSA parameter set identifier
 * @msg_len: Length of message buffer in bytes
 * @msg: DMA address of message buffer
 * @pk: DMA address of public key buffer
 * @sig: DMA address of signature buffer to verify
 */
void vcq_add_hcq_slhdsa_verify_internal(struct vcq_cmd *slot, u32 core_id, u32 param_set,
					u32 msg_len, u64 msg, u64 pk, u64 sig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1,
			      HCQ_CMD_SLHDSA_VERIFY_INTERNAL);
	slot->hwc.hcq.cmd_slhdsa_verify_internal.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_verify_internal.message_len = msg_len;
	slot->hwc.hcq.cmd_slhdsa_verify_internal.message = msg;
	slot->hwc.hcq.cmd_slhdsa_verify_internal.pk = pk;
	slot->hwc.hcq.cmd_slhdsa_verify_internal.sig = sig;
}

/**
 * vcq_add_hcq_slhdsa_pubgen() - Build an SLH-DSA public key generation VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @param_set: SLH-DSA parameter set identifier
 * @sk_len: Length of secret key buffer in bytes
 * @sk: DMA address of secret key input buffer
 * @pk: DMA address of public key output buffer
 */
void vcq_add_hcq_slhdsa_pubgen(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			       u32 sk_len, u64 sk, u64 pk)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_SLHDSA_PUBGEN);
	slot->hwc.hcq.cmd_slhdsa_pubgen.parameter_set = param_set;
	slot->hwc.hcq.cmd_slhdsa_pubgen.sk_len = sk_len;
	slot->hwc.hcq.cmd_slhdsa_pubgen.sk = sk;
	slot->hwc.hcq.cmd_slhdsa_pubgen.pk = pk;
}

/* -- LMS -- */

/**
 * vcq_add_hcq_lms_verify() - Build an LMS/HSS signature verify VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @lms_hss: LMS/HSS mode flag (0 = LMS, 1 = HSS)
 * @pk_len: Length of public key buffer in bytes
 * @sig_len: Length of signature buffer in bytes
 * @dig_len: Length of digest buffer in bytes
 * @pk: DMA address of public key buffer
 * @sig: DMA address of signature buffer
 * @dig: DMA address of digest buffer
 */
void vcq_add_hcq_lms_verify(struct vcq_cmd *slot, u32 core_id, u32 lms_hss,
			    u32 pk_len, u32 sig_len, u32 dig_len,
			    u64 pk, u64 sig, u64 dig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_LMS_VERIFY);
	slot->hwc.hcq.cmd_lms_verify.lms_hss = lms_hss;
	slot->hwc.hcq.cmd_lms_verify.pk_len = pk_len;
	slot->hwc.hcq.cmd_lms_verify.sig_len = sig_len;
	slot->hwc.hcq.cmd_lms_verify.dig_len = dig_len;
	slot->hwc.hcq.cmd_lms_verify.pk = pk;
	slot->hwc.hcq.cmd_lms_verify.sig = sig;
	slot->hwc.hcq.cmd_lms_verify.dig = dig;
}

/* -- XMSS -- */

/**
 * vcq_add_hcq_xmss_verify() - Build an XMSS/XMSS^MT signature verify VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @xmss_mt: XMSS/XMSS^MT mode flag (0 = XMSS, 1 = XMSS^MT)
 * @pk_len: Length of public key buffer in bytes
 * @sig_len: Length of signature buffer in bytes
 * @dig_len: Length of digest buffer in bytes
 * @pk: DMA address of public key buffer
 * @sig: DMA address of signature buffer
 * @dig: DMA address of digest buffer
 */
void vcq_add_hcq_xmss_verify(struct vcq_cmd *slot, u32 core_id, u32 xmss_mt,
			     u32 pk_len, u32 sig_len, u32 dig_len,
			     u64 pk, u64 sig, u64 dig)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HCQ_CMD_XMSS_VERIFY);
	slot->hwc.hcq.cmd_xmss_verify.xmss_mt = xmss_mt;
	slot->hwc.hcq.cmd_xmss_verify.pk_len = pk_len;
	slot->hwc.hcq.cmd_xmss_verify.sig_len = sig_len;
	slot->hwc.hcq.cmd_xmss_verify.dig_len = dig_len;
	slot->hwc.hcq.cmd_xmss_verify.pk = pk;
	slot->hwc.hcq.cmd_xmss_verify.sig = sig;
	slot->hwc.hcq.cmd_xmss_verify.dig = dig;
}
