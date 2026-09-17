// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- QSE Core VCQ Builders
 *
 * VCQ builder functions for ML-KEM and ML-DSA commands (plain and masked).
 * Each function populates a single vcq_cmd slot.  Callers assemble
 * complete VCQs with header + command(s) + flush, then submit via
 * cmh_tm_submit_sync().
 */

#include <linux/string.h>

#include "cmh_sys.h"

/* -- QSE flush -- */

/**
 * vcq_add_qse_flush() - Build a QSE flush VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 */
void vcq_add_qse_flush(struct vcq_cmd *slot, u32 core_id)
{
	vcq_add_flush(slot, core_id);
}

/* -- ML-KEM -- */

/**
 * vcq_add_qse_ml_kem_keygen() - Build an ML-KEM key generation VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @k: ML-KEM security parameter (k = 2, 3, or 4)
 * @flags: Command flags
 * @seed: DMA address of seed input buffer
 * @z: DMA address of implicit rejection value buffer
 * @ek: DMA address of encapsulation key output buffer
 * @dk: DMA address of decapsulation key output buffer
 * @dk_type: Decapsulation key datastore type
 * @masked: Use masked (side-channel protected) variant
 */
void vcq_add_qse_ml_kem_keygen(struct vcq_cmd *slot, u32 core_id, u32 k, u32 flags,
			       u64 seed, u64 z, u64 ek, u64 dk, u32 dk_type,
			       bool masked)
{
	u32 cmd_id = masked ? QSE_CMD_ML_KEM_KEYGEN_MASKED
			    : QSE_CMD_ML_KEM_KEYGEN;

	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd_id);
	slot->hwc.qse.cmd_ml_kem_keygen.k = k;
	slot->hwc.qse.cmd_ml_kem_keygen.flags = flags;
	slot->hwc.qse.cmd_ml_kem_keygen.seed = seed;
	slot->hwc.qse.cmd_ml_kem_keygen.z = z;
	slot->hwc.qse.cmd_ml_kem_keygen.ek = ek;
	slot->hwc.qse.cmd_ml_kem_keygen.dk = dk;
	slot->hwc.qse.cmd_ml_kem_keygen.dk_type = dk_type;
}

/**
 * vcq_add_qse_ml_kem_enc() - Build an ML-KEM encapsulation VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @k: ML-KEM security parameter (k = 2, 3, or 4)
 * @flags: Command flags
 * @coin: DMA address of encapsulation coin/randomness buffer
 * @ek: DMA address of encapsulation key input buffer
 * @ct: DMA address of ciphertext output buffer
 * @ss: DMA address of shared secret output buffer
 * @ss_type: Shared secret datastore type
 * @masked: Use masked (side-channel protected) variant
 */
void vcq_add_qse_ml_kem_enc(struct vcq_cmd *slot, u32 core_id, u32 k, u32 flags,
			    u64 coin, u64 ek, u64 ct, u64 ss, u32 ss_type,
			    bool masked)
{
	u32 cmd_id = masked ? QSE_CMD_ML_KEM_ENC_MASKED
			    : QSE_CMD_ML_KEM_ENC;

	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd_id);
	slot->hwc.qse.cmd_ml_kem_enc.k = k;
	slot->hwc.qse.cmd_ml_kem_enc.flags = flags;
	slot->hwc.qse.cmd_ml_kem_enc.coin = coin;
	slot->hwc.qse.cmd_ml_kem_enc.ek = ek;
	slot->hwc.qse.cmd_ml_kem_enc.ct = ct;
	slot->hwc.qse.cmd_ml_kem_enc.ss = ss;
	slot->hwc.qse.cmd_ml_kem_enc.ss_type = ss_type;
}

/**
 * vcq_add_qse_ml_kem_dec() - Build an ML-KEM decapsulation VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @k: ML-KEM security parameter (k = 2, 3, or 4)
 * @flags: Command flags
 * @ct: DMA address of ciphertext input buffer
 * @dk: DMA address of decapsulation key input buffer
 * @ss: DMA address of shared secret output buffer
 * @ss_type: Shared secret datastore type
 * @masked: Use masked (side-channel protected) variant
 */
void vcq_add_qse_ml_kem_dec(struct vcq_cmd *slot, u32 core_id, u32 k, u32 flags,
			    u64 ct, u64 dk, u64 ss, u32 ss_type,
			    bool masked)
{
	u32 cmd_id = masked ? QSE_CMD_ML_KEM_DEC_MASKED
			    : QSE_CMD_ML_KEM_DEC;

	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd_id);
	slot->hwc.qse.cmd_ml_kem_dec.k = k;
	slot->hwc.qse.cmd_ml_kem_dec.flags = flags;
	slot->hwc.qse.cmd_ml_kem_dec.ct = ct;
	slot->hwc.qse.cmd_ml_kem_dec.dk = dk;
	slot->hwc.qse.cmd_ml_kem_dec.ss = ss;
	slot->hwc.qse.cmd_ml_kem_dec.ss_type = ss_type;
}

/* -- ML-DSA -- */

/**
 * vcq_add_qse_ml_dsa_keygen() - Build an ML-DSA key generation VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @mode: ML-DSA mode (44, 65, or 87)
 * @flags: Command flags
 * @seed: DMA address of seed input buffer
 * @pk: DMA address of public key output buffer
 * @sk: DMA address of secret key output buffer
 * @sk_type: Secret key datastore type
 * @masked: Use masked (side-channel protected) variant
 */
void vcq_add_qse_ml_dsa_keygen(struct vcq_cmd *slot, u32 core_id, u32 mode, u32 flags,
			       u64 seed, u64 pk, u64 sk, u32 sk_type,
			       bool masked)
{
	u32 cmd_id = masked ? QSE_CMD_ML_DSA_KEYGEN_MASKED
			    : QSE_CMD_ML_DSA_KEYGEN;

	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd_id);
	slot->hwc.qse.cmd_ml_dsa_keygen.mode = mode;
	slot->hwc.qse.cmd_ml_dsa_keygen.flags = flags;
	slot->hwc.qse.cmd_ml_dsa_keygen.seed = seed;
	slot->hwc.qse.cmd_ml_dsa_keygen.pk = pk;
	slot->hwc.qse.cmd_ml_dsa_keygen.sk = sk;
	slot->hwc.qse.cmd_ml_dsa_keygen.sk_type = sk_type;
}

/**
 * vcq_add_qse_ml_dsa_sign() - Build an ML-DSA signing VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @mode: ML-DSA mode (44, 65, or 87)
 * @flags: Command flags
 * @rnd: DMA address of signing randomness buffer
 * @m: DMA address of message buffer
 * @sk: DMA address of secret key buffer
 * @sig: DMA address of signature output buffer
 * @mlen: Length of message in bytes
 * @masked: Use masked (side-channel protected) variant
 */
void vcq_add_qse_ml_dsa_sign(struct vcq_cmd *slot, u32 core_id, u32 mode, u32 flags,
			     u64 rnd, u64 m, u64 sk, u64 sig, u32 mlen,
			     bool masked)
{
	u32 cmd_id = masked ? QSE_CMD_ML_DSA_SIGN_MASKED
			    : QSE_CMD_ML_DSA_SIGN;

	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, cmd_id);
	slot->hwc.qse.cmd_ml_dsa_sign.mode = mode;
	slot->hwc.qse.cmd_ml_dsa_sign.flags = flags;
	slot->hwc.qse.cmd_ml_dsa_sign.rnd = rnd;
	slot->hwc.qse.cmd_ml_dsa_sign.m = m;
	slot->hwc.qse.cmd_ml_dsa_sign.sk = sk;
	slot->hwc.qse.cmd_ml_dsa_sign.sig = sig;
	slot->hwc.qse.cmd_ml_dsa_sign.mlen = mlen;
}

/**
 * vcq_add_qse_ml_dsa_verify() - Build an ML-DSA signature verify VCQ command
 * @slot: VCQ command slot to populate
 * @core_id: Hardware core ID for dispatch
 * @mode: ML-DSA mode (44, 65, or 87)
 * @flags: Command flags
 * @m: DMA address of message buffer
 * @pk: DMA address of public key buffer
 * @sig: DMA address of signature buffer to verify
 * @mlen: Length of message in bytes
 */
void vcq_add_qse_ml_dsa_verify(struct vcq_cmd *slot, u32 core_id, u32 mode, u32 flags,
			       u64 m, u64 pk, u64 sig, u32 mlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, QSE_CMD_ML_DSA_VERIFY);
	slot->hwc.qse.cmd_ml_dsa_verify.mode = mode;
	slot->hwc.qse.cmd_ml_dsa_verify.flags = flags;
	slot->hwc.qse.cmd_ml_dsa_verify.m = m;
	slot->hwc.qse.cmd_ml_dsa_verify.pk = pk;
	slot->hwc.qse.cmd_ml_dsa_verify.sig = sig;
	slot->hwc.qse.cmd_ml_dsa_verify.mlen = mlen;
}
