/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SYS Core VCQ Builders
 *
 * VCQ builder functions for SYS core commands (NEW, WRITE, READ,
 * FIND, GRANT, DATA, EXPORT, IMPORT).  Each builder populates one
 * vcq_cmd slot with the appropriate magic, command ID, and payload.
 *
 * Callers combine these with vcq_set_header() + vcq_add_flush()
 * and submit via cmh_tm_submit_sync().
 */

#ifndef CMH_SYS_H
#define CMH_SYS_H

#include "cmh_vcq.h"

void vcq_add_sys_new(struct vcq_cmd *slot, u64 cid, u64 ref_dma, u32 len);
void vcq_add_sys_write(struct vcq_cmd *slot, u64 ref, u64 src_dma,
		       u64 wrap_key, u32 len, u32 sys_type);
void vcq_add_sys_read(struct vcq_cmd *slot, u64 ref, u64 dst_dma,
		      u64 wrap_key, u32 len);
void vcq_add_sys_data(struct vcq_cmd *slot, u64 ref, u64 dst_dma, u32 len);
void vcq_add_sys_find(struct vcq_cmd *slot, u64 cid, u64 dst_dma, u32 len);
void vcq_add_sys_list(struct vcq_cmd *slot, u64 ref, u64 dst_dma, u32 len);
void vcq_add_sys_grant(struct vcq_cmd *slot, u64 ref, u64 read,
		       u64 write, u64 execute);
void vcq_add_sys_export(struct vcq_cmd *slot, u64 cid, u64 dst_dma,
			u64 wrap_key, u32 len);
void vcq_add_sys_import(struct vcq_cmd *slot, u64 src_dma,
			u64 wrap_key, u32 len);

/* KIC core VCQ builders */
void vcq_add_kic_hkdf1(struct vcq_cmd *slot, u64 dst, u64 base,
		       u64 label_dma, u32 key_len, u32 label_len, u32 type);
void vcq_add_kic_hkdf2(struct vcq_cmd *slot, u64 dst, u64 base, u64 salt,
		       u64 label_dma, u32 key_len, u32 label_len, u32 type);
void vcq_add_kic_aes_cmac_kdf(struct vcq_cmd *slot, u64 out_key, u64 base_key,
			      u64 label_dma, u32 key_len, u32 label_len,
			      u32 type);
void vcq_add_kic_dkek_derive(struct vcq_cmd *slot, u64 out_key, u64 base_key,
			     u32 host_id, u64 metadata_dma, u32 metadata_len);

/* DRBG core VCQ builders */
void vcq_add_drbg_reset(struct vcq_cmd *slot);
void vcq_add_drbg_config(struct vcq_cmd *slot, u32 ratio, u32 strength);
void vcq_add_drbg_datastore(struct vcq_cmd *slot, u64 ref, u32 len, u32 type);

/* QSE core VCQ builders */
void vcq_add_qse_flush(struct vcq_cmd *slot, u32 core_id);
void vcq_add_qse_ml_kem_keygen(struct vcq_cmd *slot, u32 core_id, u32 k, u32 flags,
			       u64 seed, u64 z, u64 ek, u64 dk, u32 dk_type,
			       bool masked);
void vcq_add_qse_ml_kem_enc(struct vcq_cmd *slot, u32 core_id, u32 k, u32 flags,
			    u64 coin, u64 ek, u64 ct, u64 ss, u32 ss_type,
			    bool masked);
void vcq_add_qse_ml_kem_dec(struct vcq_cmd *slot, u32 core_id, u32 k, u32 flags,
			    u64 ct, u64 dk, u64 ss, u32 ss_type,
			    bool masked);
void vcq_add_qse_ml_dsa_keygen(struct vcq_cmd *slot, u32 core_id, u32 mode, u32 flags,
			       u64 seed, u64 pk, u64 sk, u32 sk_type,
			       bool masked);
void vcq_add_qse_ml_dsa_sign(struct vcq_cmd *slot, u32 core_id, u32 mode, u32 flags,
			     u64 rnd, u64 m, u64 sk, u64 sig, u32 mlen,
			     bool masked);
void vcq_add_qse_ml_dsa_verify(struct vcq_cmd *slot, u32 core_id, u32 mode, u32 flags,
			       u64 m, u64 pk, u64 sig, u32 mlen);

/* HCQ core VCQ builders */
void vcq_add_hcq_flush(struct vcq_cmd *slot, u32 core_id);
void vcq_add_hcq_slhdsa_keygen(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			       u32 seed_len, u32 pk_len, u32 sk_len,
			       u64 seed, u64 pk, u64 sk);
void vcq_add_hcq_slhdsa_sign(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			     u32 msg_len, u32 ctx_len,
			     u64 add_random, u64 msg, u64 ctx,
			     u64 sk, u64 sig);
void vcq_add_hcq_slhdsa_sign_internal(struct vcq_cmd *slot, u32 core_id, u32 param_set,
				      u32 msg_len, u64 add_random,
				      u64 msg, u64 sk, u64 sig);
void vcq_add_hcq_slhdsa_verify(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			       u32 msg_len, u32 ctx_len,
			       u64 msg, u64 ctx, u64 pk, u64 sig);
void vcq_add_hcq_slhdsa_sign_prehash(struct vcq_cmd *slot, u32 core_id,
				     u32 cmd, u32 param_set, u32 prehash_algo,
				     u32 msg_len, u32 ctx_len,
				     u64 add_random, u64 msg, u64 ctx,
				     u64 sk, u64 sig);
void vcq_add_hcq_slhdsa_verify_prehash(struct vcq_cmd *slot, u32 core_id,
				       u32 cmd, u32 param_set, u32 prehash_algo,
				       u32 msg_len, u32 ctx_len,
				       u64 msg, u64 ctx, u64 pk, u64 sig);
void vcq_add_hcq_slhdsa_verify_internal(struct vcq_cmd *slot, u32 core_id, u32 param_set,
					u32 msg_len, u64 msg, u64 pk, u64 sig);
void vcq_add_hcq_slhdsa_pubgen(struct vcq_cmd *slot, u32 core_id, u32 param_set,
			       u32 sk_len, u64 sk, u64 pk);
void vcq_add_hcq_lms_verify(struct vcq_cmd *slot, u32 core_id, u32 lms_hss,
			    u32 pk_len, u32 sig_len, u32 dig_len,
			    u64 pk, u64 sig, u64 dig);
void vcq_add_hcq_xmss_verify(struct vcq_cmd *slot, u32 core_id, u32 xmss_mt,
			     u32 pk_len, u32 sig_len, u32 dig_len,
			     u64 pk, u64 sig, u64 dig);

/* SYS core flush */
void vcq_add_sys_flush(struct vcq_cmd *slot);

/* EAC core VCQ builder */
void vcq_add_eac_read(struct vcq_cmd *slot, u64 dst_dma, u32 len);

#endif /* CMH_SYS_H */
