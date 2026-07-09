// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH -- PQC ioctl handlers for /dev/cmh_mgmt
 *
 * ML-KEM keygen/encapsulate/decapsulate, ML-DSA keygen/sign,
 * SLH-DSA keygen/sign (pure + prehash).
 *
 * Split from cmh_mgmt.c for maintainability.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/overflow.h>

#include "cmh_mgmt.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_key.h"
#include "cmh_dma.h"
#include "cmh_config.h"
#include "cmh_pqc.h"
#include "cmh_qse_abi.h"
#include "cmh_sys_abi.h"
#include <uapi/linux/cmh_mgmt_ioctl.h>

#include <crypto/utils.h>

/* -- PQC -- ML-KEM -- */

/**
 * cmh_mgmt_ml_kem_keygen() - Handle CMH_MGMT_IOC_ML_KEM_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_ml_kem_keygen(void __user *argp)
{
	u32 qse_cid = cmh_core_default_id(CMH_CORE_QSE);

	struct cmh_ioctl_ml_kem_keygen req;
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MAX];
	u32 ek_len, dk_len, seed_len, key_flags;
	u32 qse_flags = 0;
	bool masked, ds_ref, hw_rng;
	u8 *seed_buf = NULL, *z_buf = NULL, *ek_buf, *dk_buf = NULL;
	u64 *ref_buf = NULL;
	dma_addr_t seed_dma = DMA_MAPPING_ERROR, z_dma = DMA_MAPPING_ERROR;
	dma_addr_t ek_dma, dk_dma = DMA_MAPPING_ERROR, ref_dma = DMA_MAPPING_ERROR;
	int ret, idx;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (ml_kem_k_idx(req.k) < 0)
		return -EINVAL;
	if (req.flags & ~(CMH_QSE_FLAG_MASK | CMH_FLAG_MASK))
		return -EINVAL;

	masked = !!(req.flags & CMH_QSE_FLAG_MASKED);
	ds_ref = !!(req.flags & CMH_QSE_FLAG_DS_REF);
	hw_rng = !!(req.flags & CMH_QSE_FLAG_HW_RNG);

	/*
	 * QSE keys only support PT storage -- the eSW dec/sign paths
	 * hardcode SYS_TYPE_FLAG_PT when reading the key back.
	 * QSE SCA protection uses masking (CMH_QSE_FLAG_MASKED),
	 * not the 2-share mechanism (CMH_FLAG_SCA).
	 */
	key_flags = req.flags & CMH_FLAG_MASK;
	if (key_flags && key_flags != CMH_FLAG_PT)
		return -EINVAL;
	key_flags = CMH_FLAG_PT;

	/* Masked keygen must store dk in DS -- polynomial unmasking not supported */
	if (masked && !ds_ref)
		return -EINVAL;

	ek_len = ML_KEM_EK_SIZE(req.k);
	dk_len = masked ? ML_KEM_DK_SIZE_MASKED(req.k)
			: ML_KEM_DK_SIZE(req.k);
	seed_len = masked ? QSE_SEED_LEN_MASKED : QSE_SEED_LEN;

	if (hw_rng)
		qse_flags |= QSE_FLAG_USE_RNG;
	if (ds_ref)
		qse_flags |= QSE_FLAG_USE_REF;

	ek_buf = kzalloc(ek_len, GFP_KERNEL);
	if (!ek_buf)
		return -ENOMEM;

	if (!hw_rng && req.seed && req.z) {
		seed_buf = kmalloc(seed_len, GFP_KERNEL);
		z_buf = kmalloc(seed_len, GFP_KERNEL);
		if (!seed_buf || !z_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(seed_buf, u64_to_user_ptr(req.seed),
				   seed_len) ||
		    copy_from_user(z_buf, u64_to_user_ptr(req.z), seed_len)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	if (ds_ref) {
		ref_buf = kzalloc_obj(u64, GFP_KERNEL);
		if (!ref_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
	} else {
		dk_buf = kzalloc(dk_len, GFP_KERNEL);
		if (!dk_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	/* DMA map */
	ek_dma = cmh_dma_map_single(ek_buf, ek_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ek_dma)) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (seed_buf) {
		seed_dma = cmh_dma_map_single(seed_buf, seed_len,
					      DMA_TO_DEVICE);
		z_dma = cmh_dma_map_single(z_buf, seed_len, DMA_TO_DEVICE);
		if (cmh_dma_map_error(seed_dma) || cmh_dma_map_error(z_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	if (ds_ref) {
		ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64),
					     DMA_FROM_DEVICE);
		if (cmh_dma_map_error(ref_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	} else {
		dk_dma = cmh_dma_map_single(dk_buf, dk_len, DMA_FROM_DEVICE);
		if (cmh_dma_map_error(dk_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	idx = 0;
	if (ds_ref) {
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MAX);
		idx++;
		vcq_add_sys_new(&vcq[idx++], req.dk_cid, ref_dma, dk_len);
		vcq_add_qse_ml_kem_keygen(&vcq[idx++], qse_cid, req.k, qse_flags,
					  seed_dma, z_dma,
					  ek_dma, SYS_REF_LAST,
					  SYS_TYPE_SET(key_flags,
						       CORE_ID_QSE),
					  masked);
		vcq_add_qse_flush(&vcq[idx++], qse_cid);
		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MAX,
					     1, MGMT_MBX);
	} else {
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
		idx++;
		vcq_add_qse_ml_kem_keygen(&vcq[idx++], qse_cid, req.k, qse_flags,
					  seed_dma, z_dma,
					  ek_dma, dk_dma, 0, masked);
		vcq_add_qse_flush(&vcq[idx++], qse_cid);
		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN,
					     1, MGMT_MBX);
	}

out_unmap:
	if (ds_ref && !cmh_dma_map_error(ref_dma))
		cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!ds_ref && dk_buf && !cmh_dma_map_error(dk_dma))
		cmh_dma_unmap_single(dk_dma, dk_len, DMA_FROM_DEVICE);
	if (z_buf && !cmh_dma_map_error(z_dma))
		cmh_dma_unmap_single(z_dma, seed_len, DMA_TO_DEVICE);
	if (seed_buf && !cmh_dma_map_error(seed_dma))
		cmh_dma_unmap_single(seed_dma, seed_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(ek_dma))
		cmh_dma_unmap_single(ek_dma, ek_len, DMA_FROM_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.ek), ek_buf, ek_len)) {
			ret = -EFAULT;
			goto out_free;
		}
		if (ds_ref) {
			req.dk_ref = *ref_buf;
		} else {
			if (copy_to_user(u64_to_user_ptr(req.dk),
					 dk_buf, dk_len)) {
				ret = -EFAULT;
				goto out_free;
			}
		}
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(dk_buf);
	kfree(ref_buf);
	kfree_sensitive(z_buf);
	kfree_sensitive(seed_buf);
	kfree(ek_buf);
	return ret;
}

/**
 * cmh_mgmt_ml_kem_enc() - Handle CMH_MGMT_IOC_ML_KEM_ENC ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_ml_kem_enc(void __user *argp)
{
	u32 qse_cid = cmh_core_default_id(CMH_CORE_QSE);

	struct cmh_ioctl_ml_kem_enc req;
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MIN];
	u32 ek_len, ct_len, ss_out_len;
	u32 qse_flags = 0;
	bool masked, hw_rng;
	u8 *ek_buf, *coin_buf = NULL, *ct_buf, *ss_buf;
	dma_addr_t ek_dma, coin_dma = DMA_MAPPING_ERROR, ct_dma, ss_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved || req.__reserved2[0] || req.__reserved2[1])
		return -EINVAL;
	if (ml_kem_k_idx(req.k) < 0)
		return -EINVAL;

	masked = !!(req.flags & CMH_QSE_FLAG_MASKED);
	hw_rng = !!(req.flags & CMH_QSE_FLAG_HW_RNG);

	ek_len = ML_KEM_EK_SIZE(req.k);
	ct_len = ML_KEM_CT_SIZE(req.k);
	ss_out_len = masked ? ML_KEM_SS_LEN_MASKED : ML_KEM_SS_LEN;

	if (hw_rng)
		qse_flags |= QSE_FLAG_USE_RNG;

	ek_buf = kmalloc(ek_len, GFP_KERNEL);
	ct_buf = kzalloc(ct_len, GFP_KERNEL);
	ss_buf = kzalloc(ss_out_len, GFP_KERNEL);
	if (!ek_buf || !ct_buf || !ss_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(ek_buf, u64_to_user_ptr(req.ek), ek_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (!hw_rng && req.coin) {
		u32 coin_len = masked ? QSE_SEED_LEN_MASKED : QSE_SEED_LEN;

		coin_buf = kmalloc(coin_len, GFP_KERNEL);
		if (!coin_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(coin_buf, u64_to_user_ptr(req.coin),
				   coin_len)) {
			ret = -EFAULT;
			goto out_free;
		}
		coin_dma = cmh_dma_map_single(coin_buf, coin_len,
					      DMA_TO_DEVICE);
		if (cmh_dma_map_error(coin_dma)) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	ek_dma = cmh_dma_map_single(ek_buf, ek_len, DMA_TO_DEVICE);
	ct_dma = cmh_dma_map_single(ct_buf, ct_len, DMA_FROM_DEVICE);
	ss_dma = cmh_dma_map_single(ss_buf, ss_out_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ek_dma) || cmh_dma_map_error(ct_dma) ||
	    cmh_dma_map_error(ss_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
	vcq_add_qse_ml_kem_enc(&vcq[1], qse_cid, req.k, qse_flags,
			       coin_dma, ek_dma, ct_dma, ss_dma, 0, masked);
	vcq_add_qse_flush(&vcq[2], qse_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(ss_dma))
		cmh_dma_unmap_single(ss_dma, ss_out_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ct_dma))
		cmh_dma_unmap_single(ct_dma, ct_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ek_dma))
		cmh_dma_unmap_single(ek_dma, ek_len, DMA_TO_DEVICE);
	if (coin_buf && !cmh_dma_map_error(coin_dma))
		cmh_dma_unmap_single(coin_dma,
				     masked ? QSE_SEED_LEN_MASKED
					    : QSE_SEED_LEN,
				     DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.ct), ct_buf, ct_len)) {
			ret = -EFAULT;
			goto out_free;
		}
		/* Unmask ss if masked: ss = share0 ^ share1 */
		if (masked) {
			crypto_xor(ss_buf, ss_buf + ML_KEM_SS_LEN,
				   ML_KEM_SS_LEN);
		}
		if (copy_to_user(u64_to_user_ptr(req.ss), ss_buf,
				 ML_KEM_SS_LEN)) {
			ret = -EFAULT;
			goto out_free;
		}
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(ss_buf);
	kfree(ct_buf);
	kfree(coin_buf);
	kfree(ek_buf);
	return ret;
}

/**
 * cmh_mgmt_ml_kem_dec() - Handle CMH_MGMT_IOC_ML_KEM_DEC ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_ml_kem_dec(void __user *argp)
{
	u32 qse_cid = cmh_core_default_id(CMH_CORE_QSE);

	struct cmh_ioctl_ml_kem_dec req;
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MIN];
	u32 ct_len, dk_len, ss_out_len;
	u32 qse_flags = 0;
	bool masked, ds_ref;
	u8 *ct_buf, *dk_buf = NULL, *ss_buf;
	dma_addr_t ct_dma, dk_dma = DMA_MAPPING_ERROR, ss_dma;
	u64 dk_ref;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved || req.__reserved2[0] || req.__reserved2[1])
		return -EINVAL;
	if (ml_kem_k_idx(req.k) < 0)
		return -EINVAL;

	masked = !!(req.flags & CMH_QSE_FLAG_MASKED);
	ds_ref = !!(req.flags & CMH_QSE_FLAG_DS_REF);

	ct_len = ML_KEM_CT_SIZE(req.k);
	dk_len = masked ? ML_KEM_DK_SIZE_MASKED(req.k)
			: ML_KEM_DK_SIZE(req.k);
	ss_out_len = masked ? ML_KEM_SS_LEN_MASKED : ML_KEM_SS_LEN;

	ct_buf = kmalloc(ct_len, GFP_KERNEL);
	ss_buf = kzalloc(ss_out_len, GFP_KERNEL);
	if (!ct_buf || !ss_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(ct_buf, u64_to_user_ptr(req.ct), ct_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	ct_dma = cmh_dma_map_single(ct_buf, ct_len, DMA_TO_DEVICE);
	ss_dma = cmh_dma_map_single(ss_buf, ss_out_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ct_dma) || cmh_dma_map_error(ss_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	/*
	 * dk: if DS_REF flag is set, req.dk is a DS reference.
	 * Otherwise, copy raw dk from user-space and use extmem DMA.
	 * Masked decaps requires DS ref (polynomial unmasking not supported).
	 */
	if (ds_ref) {
		dk_ref = req.dk;
		qse_flags |= QSE_FLAG_USE_REF;
	} else {
		if (masked) {
			ret = -EINVAL;
			goto out_unmap;
		}
		dk_buf = kmalloc(dk_len, GFP_KERNEL);
		if (!dk_buf) {
			ret = -ENOMEM;
			goto out_unmap;
		}
		if (copy_from_user(dk_buf, u64_to_user_ptr(req.dk), dk_len)) {
			ret = -EFAULT;
			goto out_unmap;
		}
		dk_dma = cmh_dma_map_single(dk_buf, dk_len, DMA_TO_DEVICE);
		if (cmh_dma_map_error(dk_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
		dk_ref = dk_dma;
	}

	if (ds_ref) {
		/*
		 * DS_REF decaps: CMH eSW resolves both dk and ss from DS.
		 * Phase 1: dec stores ss into SYS_REF_TEMP.
		 * Phase 2: sys_data reads ss from SYS_REF_TEMP to DMA.
		 */
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
		vcq_add_qse_ml_kem_dec(&vcq[1], qse_cid, req.k, qse_flags,
				       ct_dma, dk_ref, SYS_REF_TEMP,
				       SYS_TYPE_SET(SYS_TYPE_FLAG_PT,
						    CORE_ID_QSE),
				       masked);
		vcq_add_qse_flush(&vcq[2], qse_cid);

		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN,
					     1, MGMT_MBX);
		if (ret)
			goto out_unmap;

		/* Phase 2: extract ss from SYS_REF_TEMP */
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
		vcq_add_sys_data(&vcq[1], SYS_REF_TEMP, ss_dma,
				 ss_out_len);
		vcq_add_sys_flush(&vcq[2]);

		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN,
					     1, MGMT_MBX);
	} else {
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
		vcq_add_qse_ml_kem_dec(&vcq[1], qse_cid, req.k, qse_flags,
				       ct_dma, dk_ref, ss_dma, 0, masked);
		vcq_add_qse_flush(&vcq[2], qse_cid);

		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN,
					     1, MGMT_MBX);
	}

out_unmap:
	if (dk_buf && !cmh_dma_map_error(dk_dma))
		cmh_dma_unmap_single(dk_dma, dk_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(ss_dma))
		cmh_dma_unmap_single(ss_dma, ss_out_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ct_dma))
		cmh_dma_unmap_single(ct_dma, ct_len, DMA_TO_DEVICE);

	if (!ret) {
		if (masked) {
			crypto_xor(ss_buf, ss_buf + ML_KEM_SS_LEN,
				   ML_KEM_SS_LEN);
		}
		if (copy_to_user(u64_to_user_ptr(req.ss), ss_buf,
				 ML_KEM_SS_LEN)) {
			ret = -EFAULT;
			goto out_free;
		}
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(dk_buf);
	kfree_sensitive(ss_buf);
	kfree(ct_buf);
	return ret;
}

/* -- PQC -- ML-DSA -- */

/**
 * cmh_mgmt_ml_dsa_keygen() - Handle CMH_MGMT_IOC_ML_DSA_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_ml_dsa_keygen(void __user *argp)
{
	u32 qse_cid = cmh_core_default_id(CMH_CORE_QSE);

	struct cmh_ioctl_ml_dsa_keygen req;
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MAX];
	u32 pk_size, sk_size, seed_len, key_flags;
	u32 qse_flags = 0;
	bool masked, ds_ref, hw_rng;
	u8 *seed_buf = NULL, *pk_buf, *sk_buf = NULL;
	u64 *ref_buf = NULL;
	dma_addr_t seed_dma = DMA_MAPPING_ERROR, pk_dma;
	dma_addr_t sk_dma = DMA_MAPPING_ERROR, ref_dma = DMA_MAPPING_ERROR;
	int ret, idx, mi;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	mi = ml_dsa_mode_idx(req.mode);
	if (mi < 0)
		return -EINVAL;
	if (req.flags & ~(CMH_QSE_FLAG_MASK | CMH_FLAG_MASK))
		return -EINVAL;

	masked = !!(req.flags & CMH_QSE_FLAG_MASKED);
	ds_ref = !!(req.flags & CMH_QSE_FLAG_DS_REF);
	hw_rng = !!(req.flags & CMH_QSE_FLAG_HW_RNG);

	/*
	 * QSE keys only support PT storage -- the eSW sign path
	 * hardcodes SYS_TYPE_FLAG_PT when reading the key back.
	 * QSE SCA protection uses masking (CMH_QSE_FLAG_MASKED),
	 * not the 2-share mechanism (CMH_FLAG_SCA).
	 */
	key_flags = req.flags & CMH_FLAG_MASK;
	if (key_flags && key_flags != CMH_FLAG_PT)
		return -EINVAL;
	key_flags = CMH_FLAG_PT;

	if (masked && !ds_ref)
		return -EINVAL;

	pk_size = ml_dsa_pk_size[mi];
	sk_size = masked ? ml_dsa_sk_size_masked[mi] : ml_dsa_sk_size[mi];
	seed_len = masked ? QSE_SEED_LEN_MASKED : QSE_SEED_LEN;

	if (hw_rng)
		qse_flags |= QSE_FLAG_USE_RNG;
	if (ds_ref)
		qse_flags |= QSE_FLAG_USE_REF;

	pk_buf = kzalloc(pk_size, GFP_KERNEL);
	if (!pk_buf)
		return -ENOMEM;

	if (!hw_rng && req.seed) {
		seed_buf = kmalloc(seed_len, GFP_KERNEL);
		if (!seed_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(seed_buf, u64_to_user_ptr(req.seed),
				   seed_len)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	if (ds_ref) {
		ref_buf = kzalloc_obj(u64, GFP_KERNEL);
		if (!ref_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
	} else {
		sk_buf = kzalloc(sk_size, GFP_KERNEL);
		if (!sk_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	pk_dma = cmh_dma_map_single(pk_buf, pk_size, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(pk_dma)) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (seed_buf) {
		seed_dma = cmh_dma_map_single(seed_buf, seed_len,
					      DMA_TO_DEVICE);
		if (cmh_dma_map_error(seed_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	if (ds_ref) {
		ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64),
					     DMA_FROM_DEVICE);
		if (cmh_dma_map_error(ref_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	} else {
		sk_dma = cmh_dma_map_single(sk_buf, sk_size, DMA_FROM_DEVICE);
		if (cmh_dma_map_error(sk_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	idx = 0;
	if (ds_ref) {
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MAX);
		idx++;
		vcq_add_sys_new(&vcq[idx++], req.sk_cid, ref_dma, sk_size);
		vcq_add_qse_ml_dsa_keygen(&vcq[idx++], qse_cid, req.mode, qse_flags,
					  seed_dma, pk_dma,
					  SYS_REF_LAST,
					  SYS_TYPE_SET(key_flags,
						       CORE_ID_QSE),
					  masked);
		vcq_add_qse_flush(&vcq[idx++], qse_cid);
		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MAX,
					     1, MGMT_MBX);
	} else {
		vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
		idx++;
		vcq_add_qse_ml_dsa_keygen(&vcq[idx++], qse_cid, req.mode, qse_flags,
					  seed_dma, pk_dma,
					  sk_dma, 0, masked);
		vcq_add_qse_flush(&vcq[idx++], qse_cid);
		ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN,
					     1, MGMT_MBX);
	}

out_unmap:
	if (ds_ref && !cmh_dma_map_error(ref_dma))
		cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!ds_ref && sk_buf && !cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, sk_size, DMA_FROM_DEVICE);
	if (seed_buf && !cmh_dma_map_error(seed_dma))
		cmh_dma_unmap_single(seed_dma, seed_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, pk_size, DMA_FROM_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.pk), pk_buf, pk_size)) {
			ret = -EFAULT;
			goto out_free;
		}
		if (ds_ref) {
			req.sk_ref = *ref_buf;
		} else {
			if (copy_to_user(u64_to_user_ptr(req.sk),
					 sk_buf, sk_size)) {
				ret = -EFAULT;
				goto out_free;
			}
		}
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(sk_buf);
	kfree(ref_buf);
	kfree_sensitive(seed_buf);
	kfree(pk_buf);
	return ret;
}

/**
 * cmh_mgmt_ml_dsa_sign() - Handle CMH_MGMT_IOC_ML_DSA_SIGN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_ml_dsa_sign(void __user *argp)
{
	u32 qse_cid = cmh_core_default_id(CMH_CORE_QSE);

	struct cmh_ioctl_ml_dsa_sign req;
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MIN];
	u32 sig_size, copy_len, rnd_len;
	u32 qse_flags = 0;
	bool masked;
	u8 *m_buf, *sig_buf, *sk_buf = NULL, *rnd_buf = NULL;
	dma_addr_t m_dma = DMA_MAPPING_ERROR, sig_dma;
	dma_addr_t sk_dma = DMA_MAPPING_ERROR, rnd_dma = DMA_MAPPING_ERROR;
	u64 sk_ref;
	int mi, ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	mi = ml_dsa_mode_idx(req.mode);
	if (mi < 0)
		return -EINVAL;
	if (req.mlen > ML_DSA_MAX_MLEN && req.mlen != ML_DSA_MLEN_EXTERNAL_MU)
		return -EINVAL;

	masked = !!(req.flags & CMH_QSE_FLAG_MASKED);
	rnd_len = masked ? QSE_SEED_LEN_MASKED : QSE_SEED_LEN;
	sig_size = ml_dsa_sig_size[mi];
	copy_len = (req.mlen == ML_DSA_MLEN_EXTERNAL_MU)
			? ML_DSA_EXTMU_LEN : req.mlen;

	/*
	 * sk: if DS_REF, req.sk is a DS reference (masked sk lives in DS).
	 * Otherwise, copy raw sk from user-space.
	 * Masked sign requires DS ref (polynomial unmasking not supported).
	 */
	if (req.flags & CMH_QSE_FLAG_DS_REF) {
		sk_ref = req.sk;
		qse_flags |= QSE_FLAG_USE_REF;
	} else {
		u32 sk_size;

		if (masked)
			return -EINVAL;
		sk_size = ml_dsa_sk_size[mi];
		sk_buf = kmalloc(sk_size, GFP_KERNEL);
		if (!sk_buf)
			return -ENOMEM;
		if (copy_from_user(sk_buf, u64_to_user_ptr(req.sk), sk_size)) {
			kfree_sensitive(sk_buf);
			return -EFAULT;
		}
	}

	m_buf = kmalloc(max_t(u32, copy_len, 1), GFP_KERNEL);
	sig_buf = kzalloc(sig_size, GFP_KERNEL);
	if (!m_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_len > 0 &&
	    copy_from_user(m_buf, u64_to_user_ptr(req.m), copy_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (req.rnd) {
		rnd_buf = kmalloc(rnd_len, GFP_KERNEL);
		if (!rnd_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(rnd_buf, u64_to_user_ptr(req.rnd),
				   rnd_len)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	if (copy_len > 0) {
		m_dma = cmh_dma_map_single(m_buf, copy_len, DMA_TO_DEVICE);
		if (cmh_dma_map_error(m_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}
	sig_dma = cmh_dma_map_single(sig_buf, sig_size, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(sig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	if (sk_buf) {
		sk_dma = cmh_dma_map_single(sk_buf, ml_dsa_sk_size[mi],
					    DMA_TO_DEVICE);
		if (cmh_dma_map_error(sk_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
		sk_ref = sk_dma;
	}

	if (rnd_buf) {
		rnd_dma = cmh_dma_map_single(rnd_buf, rnd_len,
					     DMA_TO_DEVICE);
		if (cmh_dma_map_error(rnd_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
	vcq_add_qse_ml_dsa_sign(&vcq[1], qse_cid, req.mode, qse_flags,
				rnd_dma, m_dma, sk_ref, sig_dma,
				req.mlen, masked);
	vcq_add_qse_flush(&vcq[2], qse_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (rnd_buf && !cmh_dma_map_error(rnd_dma))
		cmh_dma_unmap_single(rnd_dma, rnd_len, DMA_TO_DEVICE);
	if (sk_buf && !cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, ml_dsa_sk_size[mi],
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_size, DMA_FROM_DEVICE);
	if (copy_len > 0 && !cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, copy_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.sig), sig_buf, sig_size))
			ret = -EFAULT;
	}

out_free:
	kfree(rnd_buf);
	kfree(sig_buf);
	kfree(m_buf);
	kfree_sensitive(sk_buf);
	return ret;
}

/* -- PQC -- SLH-DSA -- */

/**
 * cmh_mgmt_slhdsa_keygen() - Handle CMH_MGMT_IOC_SLHDSA_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_slhdsa_keygen(void __user *argp)
{
	u32 hcq_cid = cmh_core_default_id(CMH_CORE_HCQ);

	struct cmh_ioctl_slhdsa_keygen req;
	struct vcq_cmd vcq[HCQ_VCQ_CMDS_MAX];
	u32 pk_sz, sk_sz, seed_sz, sk_alloc, vcq_cnt, key_flags;
	bool ds_ref;
	u8 *seed_buf, *pk_buf, *sk_buf = NULL;
	u64 *ref_buf = NULL;
	dma_addr_t seed_dma, pk_dma, sk_dma = DMA_MAPPING_ERROR, ref_dma = DMA_MAPPING_ERROR;
	int ret, idx;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (req.parameter_set < 1 || req.parameter_set > HCQ_SLHDSA_PARAM_MAX)
		return -EINVAL;
	if (req.flags & ~(CMH_QSE_FLAG_DS_REF | CMH_FLAG_MASK))
		return -EINVAL;

	ds_ref = !!(req.flags & CMH_QSE_FLAG_DS_REF);

	/*
	 * QSE keys only support PT storage -- the eSW sign path
	 * hardcodes SYS_TYPE_FLAG_PT when reading the key back.
	 * HCQ core sets key type internally during keygen.
	 */
	key_flags = req.flags & CMH_FLAG_MASK;
	if (key_flags && key_flags != CMH_FLAG_PT)
		return -EINVAL;
	(void)key_flags;

	pk_sz = slhdsa_pk_size(req.parameter_set);
	sk_sz = slhdsa_sk_size(req.parameter_set);
	seed_sz = slhdsa_seed_size(req.parameter_set);

	seed_buf = kmalloc(seed_sz, GFP_KERNEL);
	pk_buf = kzalloc(pk_sz, GFP_KERNEL);
	if (!seed_buf || !pk_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(seed_buf, u64_to_user_ptr(req.seed), seed_sz)) {
		ret = -EFAULT;
		goto out_free;
	}

	/*
	 * Both paths need ref_buf for sys_new output.  Non-ds_ref also
	 * needs sk_buf (+16 for SYS header) to read back via sys_read.
	 */
	ref_buf = kzalloc(sizeof(u64), GFP_KERNEL);
	if (!ref_buf) {
		ret = -ENOMEM;
		goto out_free;
	}
	if (!ds_ref) {
		sk_alloc = sk_sz + SYS_WRAP_HDR_SIZE;
		sk_buf = kzalloc(sk_alloc, GFP_KERNEL);
		if (!sk_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	seed_dma = cmh_dma_map_single(seed_buf, seed_sz, DMA_TO_DEVICE);
	pk_dma = cmh_dma_map_single(pk_buf, pk_sz, DMA_FROM_DEVICE);
	ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(seed_dma) || cmh_dma_map_error(pk_dma) ||
	    cmh_dma_map_error(ref_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	if (!ds_ref) {
		sk_dma = cmh_dma_map_single(sk_buf, sk_alloc,
					    DMA_FROM_DEVICE);
		if (cmh_dma_map_error(sk_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	/*
	 * SLH-DSA keygen requires seed and sk as DS references.
	 * VCQ: hdr + sys_new(sk) + sys_write(seed->TEMP) + keygen + [sys_read] + flush
	 */
	idx = 0;
	if (ds_ref) {
		vcq_cnt = HCQ_VCQ_CMDS_MAX - 1; /* hdr+new+write+keygen+flush */
		vcq_set_header(&vcq[idx++], vcq_cnt);
		vcq_add_sys_new(&vcq[idx++], req.sk_cid, ref_dma,
				sk_sz);
	} else {
		vcq_cnt = HCQ_VCQ_CMDS_MAX; /* hdr+new+write+keygen+read+flush */
		vcq_set_header(&vcq[idx++], vcq_cnt);
		vcq_add_sys_new(&vcq[idx++], SYS_CID_NONE, ref_dma,
				sk_sz);
	}
	vcq_add_sys_write(&vcq[idx++], SYS_REF_TEMP, seed_dma, 0,
			  seed_sz,
			  SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_HCQ));
	vcq_add_hcq_slhdsa_keygen(&vcq[idx++], hcq_cid, req.parameter_set,
				  seed_sz, pk_sz, sk_sz,
				  SYS_REF_TEMP, pk_dma, SYS_REF_LAST);
	if (!ds_ref)
		vcq_add_sys_read(&vcq[idx++], SYS_REF_LAST, sk_dma,
				 0, sk_sz + SYS_WRAP_HDR_SIZE);
	vcq_add_hcq_flush(&vcq[idx++], hcq_cid);

	ret = cmh_tm_submit_sync_tmo(vcq, vcq_cnt, 1, MGMT_MBX,
				     cmh_tm_slow_op_timeout_jiffies());

out_unmap:
	if (!ds_ref && sk_buf && !cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, sk_alloc, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ref_dma))
		cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, pk_sz, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(seed_dma))
		cmh_dma_unmap_single(seed_dma, seed_sz, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.pk), pk_buf, pk_sz)) {
			ret = -EFAULT;
			goto out_free;
		}
		if (ds_ref) {
			req.sk_ref = *ref_buf;
		} else {
			if (copy_to_user(u64_to_user_ptr(req.sk),
					 sk_buf + SYS_WRAP_HDR_SIZE,
					 sk_sz)) {
				ret = -EFAULT;
				goto out_free;
			}
		}
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(sk_buf);
	kfree(ref_buf);
	kfree(pk_buf);
	kfree_sensitive(seed_buf);
	return ret;
}

/**
 * cmh_mgmt_slhdsa_sign() - Handle CMH_MGMT_IOC_SLHDSA_SIGN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_slhdsa_sign(void __user *argp)
{
	u32 hcq_cid = cmh_core_default_id(CMH_CORE_HCQ);

	struct cmh_ioctl_slhdsa_sign req;
	struct vcq_cmd vcq[HCQ_VCQ_CMDS_MIN];
	u32 sig_sz, n_val;
	u8 *msg_buf, *ctx_buf = NULL, *sig_buf, *rnd_buf = NULL;
	dma_addr_t msg_dma = DMA_MAPPING_ERROR, ctx_dma = DMA_MAPPING_ERROR;
	dma_addr_t sig_dma, rnd_dma = DMA_MAPPING_ERROR;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.parameter_set < 1 || req.parameter_set > HCQ_SLHDSA_PARAM_MAX)
		return -EINVAL;
	if (req.msg_len > SLHDSA_MAX_MSG_LEN)
		return -EINVAL;
	if (req.ctx_len > SLHDSA_MAX_CTX_LEN)
		return -EINVAL;

	sig_sz = slhdsa_get_sig_size(req.parameter_set);
	n_val = slhdsa_n[req.parameter_set - 1];

	msg_buf = kmalloc(max_t(u32, req.msg_len, 1), GFP_KERNEL);
	sig_buf = kzalloc(sig_sz, GFP_KERNEL);
	if (!msg_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (req.msg_len > 0 &&
	    copy_from_user(msg_buf, u64_to_user_ptr(req.msg), req.msg_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (req.ctx_len > 0 && req.ctx) {
		ctx_buf = kmalloc(req.ctx_len, GFP_KERNEL);
		if (!ctx_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(ctx_buf, u64_to_user_ptr(req.ctx),
				   req.ctx_len)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	if (req.add_random) {
		rnd_buf = kmalloc(n_val, GFP_KERNEL);
		if (!rnd_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(rnd_buf, u64_to_user_ptr(req.add_random),
				   n_val)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	sig_dma = cmh_dma_map_single(sig_buf, sig_sz, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(sig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}
	if (req.msg_len > 0) {
		msg_dma = cmh_dma_map_single(msg_buf, req.msg_len,
					     DMA_TO_DEVICE);
		if (cmh_dma_map_error(msg_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	if (ctx_buf) {
		ctx_dma = cmh_dma_map_single(ctx_buf, req.ctx_len,
					     DMA_TO_DEVICE);
		if (cmh_dma_map_error(ctx_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	if (rnd_buf) {
		rnd_dma = cmh_dma_map_single(rnd_buf, n_val, DMA_TO_DEVICE);
		if (cmh_dma_map_error(rnd_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	vcq_set_header(&vcq[0], HCQ_VCQ_CMDS_MIN);
	vcq_add_hcq_slhdsa_sign(&vcq[1], hcq_cid, req.parameter_set,
				req.msg_len, req.ctx_len,
				rnd_dma, msg_dma, ctx_dma,
				req.sk, sig_dma);
	vcq_add_hcq_flush(&vcq[2], hcq_cid);

	ret = cmh_tm_submit_sync_tmo(vcq, HCQ_VCQ_CMDS_MIN, 1, MGMT_MBX,
				     cmh_tm_slow_op_timeout_jiffies());

out_unmap:
	if (rnd_buf && !cmh_dma_map_error(rnd_dma))
		cmh_dma_unmap_single(rnd_dma, n_val, DMA_TO_DEVICE);
	if (ctx_buf && !cmh_dma_map_error(ctx_dma))
		cmh_dma_unmap_single(ctx_dma, req.ctx_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_sz, DMA_FROM_DEVICE);
	if (req.msg_len > 0 && !cmh_dma_map_error(msg_dma))
		cmh_dma_unmap_single(msg_dma, req.msg_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.sig), sig_buf, sig_sz))
			ret = -EFAULT;
	}

out_free:
	kfree(rnd_buf);
	kfree(ctx_buf);
	kfree(sig_buf);
	kfree(msg_buf);
	return ret;
}

/* -- PQC -- SLH-DSA prehash -- */

/**
 * cmh_mgmt_slhdsa_sign_prehash() - Handle CMH_MGMT_IOC_SLHDSA_SIGN_PREHASH ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_slhdsa_sign_prehash(void __user *argp)
{
	u32 hcq_cid = cmh_core_default_id(CMH_CORE_HCQ);

	struct cmh_ioctl_slhdsa_sign_prehash req;
	struct vcq_cmd vcq[HCQ_VCQ_CMDS_MIN];
	u32 sig_sz, n_val, hcq_cmd;
	u8 *msg_buf, *ctx_buf = NULL, *sig_buf, *rnd_buf = NULL;
	dma_addr_t msg_dma = DMA_MAPPING_ERROR, ctx_dma = DMA_MAPPING_ERROR;
	dma_addr_t sig_dma, rnd_dma = DMA_MAPPING_ERROR;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.parameter_set < 1 || req.parameter_set > HCQ_SLHDSA_PARAM_MAX)
		return -EINVAL;
	if (req.prehash_algo < 1 || req.prehash_algo > HCQ_SLHDSA_PREHASH_SHAKE256)
		return -EINVAL;
	if (req.msg_len > SLHDSA_MAX_MSG_LEN)
		return -EINVAL;
	if (req.ctx_len > SLHDSA_MAX_CTX_LEN)
		return -EINVAL;

	hcq_cmd = req.digest ? HCQ_CMD_SLHDSA_SIGN_PREHASH_DIGEST
			     : HCQ_CMD_SLHDSA_SIGN_PREHASH;

	sig_sz = slhdsa_get_sig_size(req.parameter_set);
	n_val = slhdsa_n[req.parameter_set - 1];

	msg_buf = kmalloc(max_t(u32, req.msg_len, 1), GFP_KERNEL);
	sig_buf = kzalloc(sig_sz, GFP_KERNEL);
	if (!msg_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (req.msg_len > 0 &&
	    copy_from_user(msg_buf, u64_to_user_ptr(req.msg), req.msg_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (req.ctx_len > 0 && req.ctx) {
		ctx_buf = kmalloc(req.ctx_len, GFP_KERNEL);
		if (!ctx_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(ctx_buf, u64_to_user_ptr(req.ctx),
				   req.ctx_len)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	if (req.add_random) {
		rnd_buf = kmalloc(n_val, GFP_KERNEL);
		if (!rnd_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(rnd_buf, u64_to_user_ptr(req.add_random),
				   n_val)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	sig_dma = cmh_dma_map_single(sig_buf, sig_sz, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(sig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}
	if (req.msg_len > 0) {
		msg_dma = cmh_dma_map_single(msg_buf, req.msg_len,
					     DMA_TO_DEVICE);
		if (cmh_dma_map_error(msg_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	if (ctx_buf) {
		ctx_dma = cmh_dma_map_single(ctx_buf, req.ctx_len,
					     DMA_TO_DEVICE);
		if (cmh_dma_map_error(ctx_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	if (rnd_buf) {
		rnd_dma = cmh_dma_map_single(rnd_buf, n_val, DMA_TO_DEVICE);
		if (cmh_dma_map_error(rnd_dma)) {
			ret = -ENOMEM;
			goto out_unmap;
		}
	}

	vcq_set_header(&vcq[0], HCQ_VCQ_CMDS_MIN);
	vcq_add_hcq_slhdsa_sign_prehash(&vcq[1], hcq_cid,
					hcq_cmd, req.parameter_set,
					req.prehash_algo,
					req.msg_len, req.ctx_len,
					rnd_dma, msg_dma, ctx_dma,
					req.sk, sig_dma);
	vcq_add_hcq_flush(&vcq[2], hcq_cid);

	ret = cmh_tm_submit_sync_tmo(vcq, HCQ_VCQ_CMDS_MIN, 1, MGMT_MBX,
				     cmh_tm_slow_op_timeout_jiffies());

out_unmap:
	if (rnd_buf && !cmh_dma_map_error(rnd_dma))
		cmh_dma_unmap_single(rnd_dma, n_val, DMA_TO_DEVICE);
	if (ctx_buf && !cmh_dma_map_error(ctx_dma))
		cmh_dma_unmap_single(ctx_dma, req.ctx_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_sz, DMA_FROM_DEVICE);
	if (req.msg_len > 0 && !cmh_dma_map_error(msg_dma))
		cmh_dma_unmap_single(msg_dma, req.msg_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.sig), sig_buf, sig_sz))
			ret = -EFAULT;
	}

out_free:
	kfree(rnd_buf);
	kfree(ctx_buf);
	kfree(sig_buf);
	kfree(msg_buf);
	return ret;
}

/* -- EAC (Error and Alarm Controller) ---- */

