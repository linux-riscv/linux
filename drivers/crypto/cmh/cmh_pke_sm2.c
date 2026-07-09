// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM2 PKE Ioctl Handlers
 *
 * SM2 (GM/T 0003) is the Chinese national public-key standard over the
 * sm2p256v1 curve (256-bit).  It defines three protocols:
 *
 *   - Signature: reuses ECDSA sign/verify with SM2_CURVE (0x18), handled
 *     by the existing cmh_mgmt_pke_ecdsa_{sign,verify}() paths.
 *   - Encryption: two-step (ENC_POINT + ENC_HASH / DEC_POINT + DEC_HASH).
 *   - Key Exchange: four-step (ECDH_KEYGEN + ID_DIGEST + ECDH + ECDH_HASH).
 *
 * This file implements the 8 SM2-specific ioctl handlers (0x16--0x1D).
 * Sign/verify/keygen/pubgen use the existing ECDSA/EC paths unchanged.
 *
 * VCQ flag convention (from eSW API):
 *   - Most SM2 commands use flags=0 (no swap).
 *   - SM2_DEC_POINT and SM2_ECDH_HASH use PKE_SWAP_FLAGS on the
 *     PKE command itself.
 *   - SM2_ECDH and SM2_ECDH_HASH also apply PKE_SWAP_FLAGS on
 *     their sys_new/sys_data VCQ phases (Weierstrass DS format).
 */

#include <linux/uaccess.h>
#include <linux/slab.h>

#include "cmh_pke.h"
#include "cmh_pke_sm2.h"
#include "cmh_sys.h"
#include "cmh_dma.h"
#include "cmh_txn.h"
#include "cmh_mgmt.h"
#include "cmh_sys_abi.h"
#include <uapi/linux/cmh_mgmt_ioctl.h>

/* SM2 fixed sizes (sm2p256v1: 256-bit curve) */
#define SM2_CLEN		32U	/* coordinate length */
#define SM2_POINT_LEN		64U	/* uncompressed EC point (x||y) */
#define SM2_SHARED_KEY_LEN	16U	/* ECDH shared key output */
#define SM2_DIGEST_LEN		32U	/* SM3 ZA digest */
#define SM2_NONCE_LEN		32U	/* nonce (when caller-provided) */
/*
 * SM2 enc_hash/dec_hash payload limit.
 *
 * The eSW PKE driver expands the GM/T 0003.4 KDF by issuing a single SM3
 * invocation per command (one 32-byte block of key stream).  Messages
 * longer than 32 bytes would require ceil(msg_len / 32) SM3 invocations
 * with an incremented counter, which the eSW does not perform; longer
 * inputs would silently produce incorrect ciphertext / plaintext.
 *
 * The eSW PKE SRAM can physically hold up to 4000 bytes of payload, but
 * that capacity is unusable until a future eSW change implements the full
 * KDF expansion.  Until then we cap the LKM at the 32-byte limit
 * documented in Documentation/ABI/testing/cmh-mgmt.
 */
#define SM2_MAX_MSG_LEN		32U	/* max plaintext for encrypt/decrypt */
#define SM2_MAX_ID_LEN		32U	/* max identity string */
#define SM2_CT_OVERHEAD		96U	/* C1(64) + C3(32) */
#define SM2_MAX_CT_LEN		(SM2_CT_OVERHEAD + SM2_MAX_MSG_LEN) /* 128 */

/* -- SM2_ECDH_KEYGEN ------------------- */

/**
 * cmh_mgmt_sm2_ecdh_keygen() - Handle CMH_MGMT_IOC_SM2_ECDH_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_ecdh_keygen(void __user *argp)
{
	struct cmh_ioctl_sm2_ecdh_keygen req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 core_id = cmh_core_default_id(CMH_CORE_PKE);
	u8 *nonce_buf, *sk_buf;
	dma_addr_t nonce_dma, sk_dma;
	int nonce_dir;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.nonce_len != 0 && req.nonce_len != SM2_NONCE_LEN)
		return -EINVAL;

	sk_buf = kzalloc(SM2_POINT_LEN, GFP_KERNEL);
	nonce_buf = kzalloc(SM2_NONCE_LEN, GFP_KERNEL);
	if (!sk_buf || !nonce_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	/*
	 * nonce_len=32: caller provides ephemeral scalar r (DMA_TO_DEVICE).
	 * nonce_len=0:  HW generates r and writes it back (DMA_FROM_DEVICE).
	 * The caller MUST supply a valid nonce pointer in both cases.
	 */
	if (req.nonce_len) {
		if (copy_from_user(nonce_buf, u64_to_user_ptr(req.nonce),
				   SM2_NONCE_LEN)) {
			ret = -EFAULT;
			goto out_free;
		}
		nonce_dir = DMA_TO_DEVICE;
	} else {
		nonce_dir = DMA_FROM_DEVICE;
	}

	sk_dma = cmh_dma_map_single(sk_buf, SM2_POINT_LEN, DMA_FROM_DEVICE);
	nonce_dma = cmh_dma_map_single(nonce_buf, SM2_NONCE_LEN, nonce_dir);
	if (cmh_dma_map_error(sk_dma) || cmh_dma_map_error(nonce_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_sm2_ecdh_keygen(&vcq[1], core_id, nonce_dma, sk_dma,
				    req.nonce_len, 0);
	vcq_add_pke_flush(&vcq[2], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(nonce_dma))
		cmh_dma_unmap_single(nonce_dma, SM2_NONCE_LEN, nonce_dir);
	if (!cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, SM2_POINT_LEN, DMA_FROM_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.session_key),
				 sk_buf, SM2_POINT_LEN))
			ret = -EFAULT;
		/* Write back HW-generated nonce when nonce_len=0 */
		if (!ret && !req.nonce_len) {
			if (copy_to_user(u64_to_user_ptr(req.nonce),
					 nonce_buf, SM2_NONCE_LEN))
				ret = -EFAULT;
		}
	}

out_free:
	kfree_sensitive(nonce_buf);
	kfree_sensitive(sk_buf);
	return ret;
}

/* -- SM2_ECDH -------------------------- */

/**
 * cmh_mgmt_sm2_ecdh() - Handle CMH_MGMT_IOC_SM2_ECDH ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_ecdh(void __user *argp)
{
	struct cmh_ioctl_sm2_ecdh req;
	/* Phase 1: hdr + sys_new + sm2_ecdh + pke_flush */
	struct vcq_cmd vcq[4];
	u32 sp_type, core_id;
	u8 *nonce_buf, *peer_pk_buf, *peer_sk_buf, *sp_buf;
	u64 *ref_buf;
	dma_addr_t nonce_dma, peer_pk_dma, peer_sk_dma, sp_dma, ref_dma;
	int nonce_dir, ret, idx;
	bool keep_ds;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.nonce_len != 0 && req.nonce_len != SM2_NONCE_LEN)
		return -EINVAL;

	keep_ds = (req.shared_point_ref != 0);
	sp_type = SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_PKE);
	core_id = cmh_core_default_id(CMH_CORE_PKE);

	peer_pk_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	peer_sk_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	sp_buf = kzalloc(SM2_POINT_LEN, GFP_KERNEL);
	ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	nonce_buf = kzalloc(SM2_NONCE_LEN, GFP_KERNEL);
	if (!peer_pk_buf || !peer_sk_buf || !sp_buf || !ref_buf ||
	    !nonce_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(peer_pk_buf, u64_to_user_ptr(req.peer_public_key),
			   SM2_POINT_LEN) ||
	    copy_from_user(peer_sk_buf, u64_to_user_ptr(req.peer_session_key),
			   SM2_POINT_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (req.nonce_len) {
		if (copy_from_user(nonce_buf, u64_to_user_ptr(req.nonce),
				   SM2_NONCE_LEN)) {
			ret = -EFAULT;
			goto out_free;
		}
		nonce_dir = DMA_TO_DEVICE;
	} else {
		nonce_dir = DMA_FROM_DEVICE;
	}

	peer_pk_dma = cmh_dma_map_single(peer_pk_buf, SM2_POINT_LEN,
					 DMA_TO_DEVICE);
	peer_sk_dma = cmh_dma_map_single(peer_sk_buf, SM2_POINT_LEN,
					 DMA_TO_DEVICE);
	sp_dma = cmh_dma_map_single(sp_buf, SM2_POINT_LEN, DMA_FROM_DEVICE);
	ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	nonce_dma = cmh_dma_map_single(nonce_buf, SM2_NONCE_LEN, nonce_dir);

	if (cmh_dma_map_error(peer_pk_dma) || cmh_dma_map_error(peer_sk_dma) ||
	    cmh_dma_map_error(sp_dma) || cmh_dma_map_error(ref_dma) ||
	    cmh_dma_map_error(nonce_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	/* Phase 1: sys_new(shared_point_ref) + SM2_ECDH(->SYS_REF_LAST) */
	idx = 0;
	vcq_set_header(&vcq[idx++], 4);
	vcq_add_sys_new(&vcq[idx], 0, ref_dma, SM2_POINT_LEN);
	vcq[idx++].id |= PKE_SWAP_FLAGS;
	vcq_add_pke_sm2_ecdh(&vcq[idx++], core_id, req.nonce_len, SM2_CLEN,
			     nonce_dma, peer_pk_dma, peer_sk_dma,
			     req.key_ref, SYS_REF_LAST, sp_type, 0);
	vcq_add_pke_flush(&vcq[idx++], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, 4, 1, MGMT_MBX);
	if (ret)
		goto out_unmap;

	if (!keep_ds) {
		/* Sync bounce buffer so CPU sees the DMA-written ref */
		cmh_dma_sync_for_cpu(ref_dma, sizeof(u64), DMA_FROM_DEVICE);

		/* Phase 2: read shared point from DS -> DMA, consuming the slot */
		vcq_set_header(&vcq[0], 3);
		vcq_add_sys_data(&vcq[1], *ref_buf, sp_dma, SM2_POINT_LEN);
		vcq[1].id |= PKE_SWAP_FLAGS;
		vcq_add_sys_flush(&vcq[2]);

		ret = cmh_tm_submit_sync_mbx(vcq, 3, 1, MGMT_MBX);
	}

out_unmap:
	if (!cmh_dma_map_error(nonce_dma))
		cmh_dma_unmap_single(nonce_dma, SM2_NONCE_LEN, nonce_dir);
	if (!cmh_dma_map_error(ref_dma))
		cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(sp_dma))
		cmh_dma_unmap_single(sp_dma, SM2_POINT_LEN, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(peer_sk_dma))
		cmh_dma_unmap_single(peer_sk_dma, SM2_POINT_LEN,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(peer_pk_dma))
		cmh_dma_unmap_single(peer_pk_dma, SM2_POINT_LEN,
				     DMA_TO_DEVICE);

	if (!ret) {
		if (!keep_ds) {
			if (copy_to_user(u64_to_user_ptr(req.shared_point),
					 sp_buf, SM2_POINT_LEN))
				ret = -EFAULT;
		} else {
			/* Return DS ref for ECDH_HASH to consume */
			u64 __user *sp_refp = (__u64 __user *)
				u64_to_user_ptr(req.shared_point_ref);

			if (put_user(*ref_buf, sp_refp)) {
				/*
				 * Failed to deliver the DS ref to
				 * userspace.  Logically delete the
				 * orphaned slot so it does not leak.
				 */
				vcq_set_header(&vcq[0], 3);
				vcq_add_sys_grant(&vcq[1], *ref_buf,
						  0, 0, 0);
				vcq_add_sys_flush(&vcq[2]);
				cmh_tm_submit_sync_mbx(vcq, 3, 1,
						       MGMT_MBX);
				dev_warn(cmh_dev(), "SM2 ECDH put_user failed, DS slot cleaned up\n");
				ret = -EFAULT;
			}
		}
		/* Write back HW-generated nonce when nonce_len=0 */
		if (!ret && !req.nonce_len) {
			if (copy_to_user(u64_to_user_ptr(req.nonce),
					 nonce_buf, SM2_NONCE_LEN))
				ret = -EFAULT;
		}
	}

out_free:
	kfree_sensitive(nonce_buf);
	kfree(ref_buf);
	kfree_sensitive(sp_buf);
	kfree(peer_sk_buf);
	kfree(peer_pk_buf);
	return ret;
}

/* -- SM2_DEC_POINT --------------------- */

/**
 * cmh_mgmt_sm2_dec_point() - Handle CMH_MGMT_IOC_SM2_DEC_POINT ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_dec_point(void __user *argp)
{
	struct cmh_ioctl_sm2_dec_point req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 core_id = cmh_core_default_id(CMH_CORE_PKE);
	u8 *ct_buf, *dp_buf;
	dma_addr_t ct_dma, dp_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.ciphertext_len <= SM2_CT_OVERHEAD ||
	    req.ciphertext_len > SM2_MAX_CT_LEN)
		return -EINVAL;

	/* Only need C1 (first 64 bytes) for the sidecar */
	ct_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	dp_buf = kzalloc(SM2_POINT_LEN, GFP_KERNEL);
	if (!ct_buf || !dp_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(ct_buf, u64_to_user_ptr(req.ciphertext),
			   SM2_POINT_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	ct_dma = cmh_dma_map_single(ct_buf, SM2_POINT_LEN, DMA_TO_DEVICE);
	dp_dma = cmh_dma_map_single(dp_buf, SM2_POINT_LEN, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ct_dma) || cmh_dma_map_error(dp_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_sm2_dec_point(&vcq[1], core_id, req.ciphertext_len, SM2_CLEN,
				  ct_dma, dp_dma, req.key_ref,
				  PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[2], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(dp_dma))
		cmh_dma_unmap_single(dp_dma, SM2_POINT_LEN, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ct_dma))
		cmh_dma_unmap_single(ct_dma, SM2_POINT_LEN, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.dec_point),
				 dp_buf, SM2_POINT_LEN))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(dp_buf);
	kfree(ct_buf);
	return ret;
}

/* -- SM2_ENC_POINT --------------------- */

/**
 * cmh_mgmt_sm2_enc_point() - Handle CMH_MGMT_IOC_SM2_ENC_POINT ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_enc_point(void __user *argp)
{
	struct cmh_ioctl_sm2_enc_point req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 core_id = cmh_core_default_id(CMH_CORE_PKE);
	u8 *nonce_buf = NULL, *pk_buf, *ct_buf, *ep_buf;
	dma_addr_t nonce_dma = DMA_MAPPING_ERROR, pk_dma, ct_dma, ep_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.nonce_len != 0 && req.nonce_len != SM2_NONCE_LEN)
		return -EINVAL;

	pk_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	ct_buf = kzalloc(SM2_POINT_LEN, GFP_KERNEL);
	ep_buf = kzalloc(SM2_POINT_LEN, GFP_KERNEL);
	if (!pk_buf || !ct_buf || !ep_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(pk_buf, u64_to_user_ptr(req.public_key),
			   SM2_POINT_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (req.nonce_len) {
		nonce_buf = kmalloc(SM2_NONCE_LEN, GFP_KERNEL);
		if (!nonce_buf) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(nonce_buf, u64_to_user_ptr(req.nonce),
				   SM2_NONCE_LEN)) {
			ret = -EFAULT;
			goto out_free;
		}
	}

	pk_dma = cmh_dma_map_single(pk_buf, SM2_POINT_LEN, DMA_TO_DEVICE);
	ct_dma = cmh_dma_map_single(ct_buf, SM2_POINT_LEN, DMA_FROM_DEVICE);
	ep_dma = cmh_dma_map_single(ep_buf, SM2_POINT_LEN, DMA_FROM_DEVICE);
	if (nonce_buf)
		nonce_dma = cmh_dma_map_single(nonce_buf, SM2_NONCE_LEN,
					       DMA_TO_DEVICE);
	if (cmh_dma_map_error(pk_dma) || cmh_dma_map_error(ct_dma) ||
	    cmh_dma_map_error(ep_dma) ||
	    (nonce_buf && cmh_dma_map_error(nonce_dma))) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_sm2_enc_point(&vcq[1], core_id, nonce_dma, pk_dma, ct_dma,
				  ep_dma, req.nonce_len, 0);
	vcq_add_pke_flush(&vcq[2], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (nonce_buf && !cmh_dma_map_error(nonce_dma))
		cmh_dma_unmap_single(nonce_dma, SM2_NONCE_LEN, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(ep_dma))
		cmh_dma_unmap_single(ep_dma, SM2_POINT_LEN, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ct_dma))
		cmh_dma_unmap_single(ct_dma, SM2_POINT_LEN, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, SM2_POINT_LEN, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.ciphertext),
				 ct_buf, SM2_POINT_LEN) ||
		    copy_to_user(u64_to_user_ptr(req.enc_point),
				 ep_buf, SM2_POINT_LEN))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(nonce_buf);
	kfree(ep_buf);
	kfree(ct_buf);
	kfree(pk_buf);
	return ret;
}

/* -- SM2_ID_DIGEST --------------------- */

/**
 * cmh_mgmt_sm2_id_digest() - Handle CMH_MGMT_IOC_SM2_ID_DIGEST ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_id_digest(void __user *argp)
{
	struct cmh_ioctl_sm2_id_digest req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 core_id = cmh_core_default_id(CMH_CORE_PKE);
	u8 *id_buf, *pk_buf, *dig_buf;
	dma_addr_t id_dma, pk_dma, dig_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.id_len || req.id_len > SM2_MAX_ID_LEN)
		return -EINVAL;

	id_buf = kmalloc(req.id_len, GFP_KERNEL);
	pk_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	dig_buf = kzalloc(SM2_DIGEST_LEN, GFP_KERNEL);
	if (!id_buf || !pk_buf || !dig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(id_buf, u64_to_user_ptr(req.id), req.id_len) ||
	    copy_from_user(pk_buf, u64_to_user_ptr(req.public_key),
			   SM2_POINT_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	id_dma = cmh_dma_map_single(id_buf, req.id_len, DMA_TO_DEVICE);
	pk_dma = cmh_dma_map_single(pk_buf, SM2_POINT_LEN, DMA_TO_DEVICE);
	dig_dma = cmh_dma_map_single(dig_buf, SM2_DIGEST_LEN,
				     DMA_FROM_DEVICE);
	if (cmh_dma_map_error(id_dma) || cmh_dma_map_error(pk_dma) ||
	    cmh_dma_map_error(dig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_sm2_id_digest(&vcq[1], core_id, id_dma, pk_dma, dig_dma,
				  req.id_len, 0);
	vcq_add_pke_flush(&vcq[2], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(dig_dma))
		cmh_dma_unmap_single(dig_dma, SM2_DIGEST_LEN,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, SM2_POINT_LEN, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(id_dma))
		cmh_dma_unmap_single(id_dma, req.id_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.digest),
				 dig_buf, SM2_DIGEST_LEN))
			ret = -EFAULT;
	}

out_free:
	kfree(dig_buf);
	kfree(pk_buf);
	kfree(id_buf);
	return ret;
}

/* -- SM2_ECDH_HASH --------------------- */

/**
 * cmh_mgmt_sm2_ecdh_hash() - Handle CMH_MGMT_IOC_SM2_ECDH_HASH ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_ecdh_hash(void __user *argp)
{
	struct cmh_ioctl_sm2_ecdh_hash req;
	/* Phase 1: hdr + sys_new + sm2_ecdh_hash + pke_flush; reused for Phase 2 */
	struct vcq_cmd vcq[4];
	u32 sk_type, core_id;
	u8 *peer_dig_buf, *dig_buf, *sk_buf;
	u64 *ref_buf;
	dma_addr_t peer_dig_dma, dig_dma, sk_dma, ref_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;

	sk_type = SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_PKE);
	core_id = cmh_core_default_id(CMH_CORE_PKE);

	peer_dig_buf = kmalloc(SM2_DIGEST_LEN, GFP_KERNEL);
	dig_buf = kmalloc(SM2_DIGEST_LEN, GFP_KERNEL);
	sk_buf = kzalloc(SM2_SHARED_KEY_LEN, GFP_KERNEL);
	ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	if (!peer_dig_buf || !dig_buf || !sk_buf || !ref_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(peer_dig_buf, u64_to_user_ptr(req.peer_id_digest),
			   SM2_DIGEST_LEN) ||
	    copy_from_user(dig_buf, u64_to_user_ptr(req.id_digest),
			   SM2_DIGEST_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	peer_dig_dma = cmh_dma_map_single(peer_dig_buf, SM2_DIGEST_LEN,
					  DMA_TO_DEVICE);
	dig_dma = cmh_dma_map_single(dig_buf, SM2_DIGEST_LEN, DMA_TO_DEVICE);
	sk_dma = cmh_dma_map_single(sk_buf, SM2_SHARED_KEY_LEN,
				    DMA_FROM_DEVICE);
	ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(peer_dig_dma) || cmh_dma_map_error(dig_dma) ||
	    cmh_dma_map_error(sk_dma) || cmh_dma_map_error(ref_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	/*
	 * Phase 1: sys_new(shared_key_ref) + SM2_ECDH_HASH
	 * The shared_point_ref from the ECDH step is passed directly
	 * as a DS reference -- the eSW hub reads it from DS.
	 */
	vcq_set_header(&vcq[0], 4);
	vcq_add_sys_new(&vcq[1], 0, ref_dma, SM2_SHARED_KEY_LEN);
	vcq[1].id |= PKE_SWAP_FLAGS;
	vcq_add_pke_sm2_ecdh_hash(&vcq[2], core_id, peer_dig_dma, dig_dma,
				  req.shared_point_ref, SYS_REF_LAST,
				  sk_type, PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[3], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, 4, 1, MGMT_MBX);
	if (ret)
		goto out_unmap;

	/* Sync bounce buffer so CPU sees the DMA-written ref */
	cmh_dma_sync_for_cpu(ref_dma, sizeof(u64), DMA_FROM_DEVICE);

	/* Phase 2: read shared key from DS -> DMA */
	vcq_set_header(&vcq[0], 3);
	vcq_add_sys_data(&vcq[1], *ref_buf, sk_dma, SM2_SHARED_KEY_LEN);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, 3, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(ref_dma))
		cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, SM2_SHARED_KEY_LEN,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(dig_dma))
		cmh_dma_unmap_single(dig_dma, SM2_DIGEST_LEN, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(peer_dig_dma))
		cmh_dma_unmap_single(peer_dig_dma, SM2_DIGEST_LEN,
				     DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.shared_key),
				 sk_buf, SM2_SHARED_KEY_LEN))
			ret = -EFAULT;
	}

out_free:
	kfree(ref_buf);
	kfree_sensitive(sk_buf);
	kfree(dig_buf);
	kfree(peer_dig_buf);
	return ret;
}

/* -- SM2_DEC_HASH ---------------------- */

/**
 * cmh_mgmt_sm2_dec_hash() - Handle CMH_MGMT_IOC_SM2_DEC_HASH ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_dec_hash(void __user *argp)
{
	struct cmh_ioctl_sm2_dec_hash req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 msg_len, core_id;
	u8 *ct_buf, *dp_buf, *pt_buf;
	dma_addr_t ct_dma, dp_dma, pt_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.ciphertext_len <= SM2_CT_OVERHEAD ||
	    req.ciphertext_len > SM2_MAX_CT_LEN)
		return -EINVAL;

	msg_len = req.ciphertext_len - SM2_CT_OVERHEAD;
	core_id = cmh_core_default_id(CMH_CORE_PKE);

	ct_buf = kmalloc(req.ciphertext_len, GFP_KERNEL);
	dp_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	pt_buf = kzalloc(msg_len, GFP_KERNEL);
	if (!ct_buf || !dp_buf || !pt_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(ct_buf, u64_to_user_ptr(req.ciphertext),
			   req.ciphertext_len) ||
	    copy_from_user(dp_buf, u64_to_user_ptr(req.dec_point),
			   SM2_POINT_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	ct_dma = cmh_dma_map_single(ct_buf, req.ciphertext_len,
				    DMA_TO_DEVICE);
	dp_dma = cmh_dma_map_single(dp_buf, SM2_POINT_LEN, DMA_TO_DEVICE);
	pt_dma = cmh_dma_map_single(pt_buf, msg_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ct_dma) || cmh_dma_map_error(dp_dma) ||
	    cmh_dma_map_error(pt_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_sm2_dec_hash(&vcq[1], core_id, ct_dma, dp_dma, pt_dma,
				 req.ciphertext_len, 0);
	vcq_add_pke_flush(&vcq[2], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(pt_dma))
		cmh_dma_unmap_single(pt_dma, msg_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(dp_dma))
		cmh_dma_unmap_single(dp_dma, SM2_POINT_LEN, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(ct_dma))
		cmh_dma_unmap_single(ct_dma, req.ciphertext_len,
				     DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.plaintext),
				 pt_buf, msg_len))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(pt_buf);
	kfree_sensitive(dp_buf);
	kfree(ct_buf);
	return ret;
}

/* -- SM2_ENC_HASH ---------------------- */

/**
 * cmh_mgmt_sm2_enc_hash() - Handle CMH_MGMT_IOC_SM2_ENC_HASH ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_sm2_enc_hash(void __user *argp)
{
	struct cmh_ioctl_sm2_enc_hash req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 ct_len, core_id;
	u8 *msg_buf, *ep_buf, *ct_buf;
	dma_addr_t msg_dma, ep_dma, ct_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.message_len || req.message_len > SM2_MAX_MSG_LEN)
		return -EINVAL;

	ct_len = SM2_CT_OVERHEAD + req.message_len;
	core_id = cmh_core_default_id(CMH_CORE_PKE);

	msg_buf = kmalloc(req.message_len, GFP_KERNEL);
	ep_buf = kmalloc(SM2_POINT_LEN, GFP_KERNEL);
	ct_buf = kzalloc(ct_len, GFP_KERNEL);
	if (!msg_buf || !ep_buf || !ct_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(msg_buf, u64_to_user_ptr(req.message),
			   req.message_len) ||
	    copy_from_user(ep_buf, u64_to_user_ptr(req.enc_point),
			   SM2_POINT_LEN)) {
		ret = -EFAULT;
		goto out_free;
	}

	msg_dma = cmh_dma_map_single(msg_buf, req.message_len, DMA_TO_DEVICE);
	ep_dma = cmh_dma_map_single(ep_buf, SM2_POINT_LEN, DMA_TO_DEVICE);
	ct_dma = cmh_dma_map_single(ct_buf, ct_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(msg_dma) || cmh_dma_map_error(ep_dma) ||
	    cmh_dma_map_error(ct_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_sm2_enc_hash(&vcq[1], core_id, msg_dma, ep_dma, ct_dma,
				 req.message_len, 0);
	vcq_add_pke_flush(&vcq[2], core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(ct_dma))
		cmh_dma_unmap_single(ct_dma, ct_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ep_dma))
		cmh_dma_unmap_single(ep_dma, SM2_POINT_LEN, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(msg_dma))
		cmh_dma_unmap_single(msg_dma, req.message_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.ciphertext),
				 ct_buf, ct_len))
			ret = -EFAULT;
	}

out_free:
	kfree(ct_buf);
	kfree(ep_buf);
	kfree_sensitive(msg_buf);
	return ret;
}
