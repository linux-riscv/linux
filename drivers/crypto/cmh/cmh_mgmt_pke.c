// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH -- PKE ioctl handlers for /dev/cmh_mgmt
 *
 * RSA encrypt/decrypt/CRT/keygen, ECDSA sign, ECDH/keygen,
 * EdDSA sign/verify, EC keygen/pubgen.
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
#include "cmh_pke.h"
#include "cmh_pke_abi.h"
#include "cmh_sys_abi.h"
#include <uapi/linux/cmh_mgmt_ioctl.h>

#include <crypto/utils.h>

/* -- PKE ioctl helpers ------------------- */

/*
 * Maximum PKE operand size: 512 bytes (RSA 4096-bit),
 * or 2 * 68 = 136 bytes (P-521 coordinate pair).
 */
#define PKE_MAX_OPERAND	512

/* Validate curve ID and return coordinate length; 0 = invalid */
static u32 cmh_pke_validate_curve(u32 curve)
{
	return pke_curve_clen(curve);
}

/**
 * cmh_mgmt_pke_rsa_enc() - Handle CMH_MGMT_IOC_PKE_RSA_ENC ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_rsa_enc(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_rsa_enc req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 n_len, e_padded;
	u8 *e_buf, *n_buf, *m_buf, *c_buf;
	dma_addr_t e_dma, n_dma, m_dma, c_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (req.bits < PKE_RSA_MIN_BITS || req.bits > PKE_RSA_MAX_BITS)
		return -EINVAL;
	if (!req.e_len || req.e_len > PKE_MAX_OPERAND)
		return -EINVAL;

	n_len = req.bits / 8;
	e_padded = ALIGN(req.e_len, 4);

	e_buf = kzalloc(e_padded, GFP_KERNEL);
	n_buf = kmalloc(n_len, GFP_KERNEL);
	m_buf = kmalloc(n_len, GFP_KERNEL);
	c_buf = kzalloc(n_len, GFP_KERNEL);
	if (!e_buf || !n_buf || !m_buf || !c_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	/* Right-align exponent in zero-padded buffer for DMA alignment */
	if (copy_from_user(e_buf + e_padded - req.e_len,
			   u64_to_user_ptr(req.e), req.e_len) ||
	    copy_from_user(n_buf, u64_to_user_ptr(req.n), n_len) ||
	    copy_from_user(m_buf, u64_to_user_ptr(req.input), n_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	e_dma = cmh_dma_map_single(e_buf, e_padded, DMA_TO_DEVICE);
	n_dma = cmh_dma_map_single(n_buf, n_len, DMA_TO_DEVICE);
	m_dma = cmh_dma_map_single(m_buf, n_len, DMA_TO_DEVICE);
	c_dma = cmh_dma_map_single(c_buf, n_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(e_dma) || cmh_dma_map_error(n_dma) ||
	    cmh_dma_map_error(m_dma) || cmh_dma_map_error(c_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_rsa_enc(&vcq[1], pke_cid, req.bits, e_padded,
			    e_dma, n_dma, m_dma, c_dma, PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(c_dma))
		cmh_dma_unmap_single(c_dma, n_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, n_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(n_dma))
		cmh_dma_unmap_single(n_dma, n_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(e_dma))
		cmh_dma_unmap_single(e_dma, e_padded, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.output), c_buf, n_len))
			ret = -EFAULT;
	}

out_free:
	kfree(c_buf);
	kfree_sensitive(m_buf);
	kfree(n_buf);
	kfree(e_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_rsa_dec() - Handle CMH_MGMT_IOC_PKE_RSA_DEC ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_rsa_dec(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_rsa_dec req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 n_len, e_padded;
	u8 *e_buf, *n_buf, *c_buf, *m_buf;
	dma_addr_t e_dma, n_dma, c_dma, m_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (req.bits < PKE_RSA_MIN_BITS || req.bits > PKE_RSA_MAX_BITS)
		return -EINVAL;
	if (!req.e_len || req.e_len > PKE_MAX_OPERAND)
		return -EINVAL;

	n_len = req.bits / 8;
	e_padded = ALIGN(req.e_len, 4);

	e_buf = kzalloc(e_padded, GFP_KERNEL);
	n_buf = kmalloc(n_len, GFP_KERNEL);
	c_buf = kmalloc(n_len, GFP_KERNEL);
	m_buf = kzalloc(n_len, GFP_KERNEL);
	if (!e_buf || !n_buf || !c_buf || !m_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	/* Right-align exponent in zero-padded buffer for DMA alignment */
	if (copy_from_user(e_buf + e_padded - req.e_len,
			   u64_to_user_ptr(req.e), req.e_len) ||
	    copy_from_user(n_buf, u64_to_user_ptr(req.n), n_len) ||
	    copy_from_user(c_buf, u64_to_user_ptr(req.input), n_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	e_dma = cmh_dma_map_single(e_buf, e_padded, DMA_TO_DEVICE);
	n_dma = cmh_dma_map_single(n_buf, n_len, DMA_TO_DEVICE);
	c_dma = cmh_dma_map_single(c_buf, n_len, DMA_TO_DEVICE);
	m_dma = cmh_dma_map_single(m_buf, n_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(e_dma) || cmh_dma_map_error(n_dma) ||
	    cmh_dma_map_error(c_dma) || cmh_dma_map_error(m_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_rsa_dec(&vcq[1], pke_cid, req.bits, e_padded,
			    e_dma, n_dma, c_dma, m_dma, req.key_ref,
			    PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, n_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(c_dma))
		cmh_dma_unmap_single(c_dma, n_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(n_dma))
		cmh_dma_unmap_single(n_dma, n_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(e_dma))
		cmh_dma_unmap_single(e_dma, e_padded, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.output), m_buf, n_len))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(m_buf);
	kfree(c_buf);
	kfree(n_buf);
	kfree(e_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_rsa_crt_dec() - Handle CMH_MGMT_IOC_PKE_RSA_CRT_DEC ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_rsa_crt_dec(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_rsa_crt_dec req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 n_len, e_padded;
	u8 *e_buf, *n_buf, *c_buf, *m_buf;
	dma_addr_t e_dma, n_dma, c_dma, m_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (req.bits < PKE_RSA_MIN_BITS || req.bits > PKE_RSA_MAX_BITS)
		return -EINVAL;
	if (!req.e_len || req.e_len > PKE_MAX_OPERAND)
		return -EINVAL;

	n_len = req.bits / 8;
	e_padded = ALIGN(req.e_len, 4);

	e_buf = kzalloc(e_padded, GFP_KERNEL);
	n_buf = kmalloc(n_len, GFP_KERNEL);
	c_buf = kmalloc(n_len, GFP_KERNEL);
	m_buf = kzalloc(n_len, GFP_KERNEL);
	if (!e_buf || !n_buf || !c_buf || !m_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	/* Right-align exponent in zero-padded buffer for DMA alignment */
	if (copy_from_user(e_buf + e_padded - req.e_len,
			   u64_to_user_ptr(req.e), req.e_len) ||
	    copy_from_user(n_buf, u64_to_user_ptr(req.n), n_len) ||
	    copy_from_user(c_buf, u64_to_user_ptr(req.input), n_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	e_dma = cmh_dma_map_single(e_buf, e_padded, DMA_TO_DEVICE);
	n_dma = cmh_dma_map_single(n_buf, n_len, DMA_TO_DEVICE);
	c_dma = cmh_dma_map_single(c_buf, n_len, DMA_TO_DEVICE);
	m_dma = cmh_dma_map_single(m_buf, n_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(e_dma) || cmh_dma_map_error(n_dma) ||
	    cmh_dma_map_error(c_dma) || cmh_dma_map_error(m_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_rsa_crt_dec(&vcq[1], pke_cid, req.bits, e_padded,
				e_dma, n_dma, c_dma, m_dma, req.crt_ref,
				PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, n_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(c_dma))
		cmh_dma_unmap_single(c_dma, n_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(n_dma))
		cmh_dma_unmap_single(n_dma, n_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(e_dma))
		cmh_dma_unmap_single(e_dma, e_padded, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.output), m_buf, n_len))
			ret = -EFAULT;
	}

out_free:
	kfree_sensitive(m_buf);
	kfree(c_buf);
	kfree(n_buf);
	kfree(e_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_rsa_keygen() - Handle CMH_MGMT_IOC_PKE_RSA_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_rsa_keygen(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_rsa_keygen req;
	/*
	 * When has_crt, we use a two-VCQ approach (CRI pattern):
	 *   VCQ #1: header + SYS_NEW(d) + SYS_NEW(crt) + SYS_FLUSH  (4 slots)
	 *   VCQ #2: header + RSA_KEYGEN + PKE_FLUSH + SYS_FLUSH       (4 slots)
	 * Without CRT, single VCQ:
	 *   header + SYS_NEW(d) + RSA_KEYGEN + PKE_FLUSH + SYS_FLUSH  (5 slots)
	 */
	struct vcq_cmd vcq[5];
	u32 n_len, e_padded, key_flags, d_ds_len, crt_ds_len;
	u8 *e_buf, *n_buf;
	u64 *d_ref_buf, *crt_ref_buf;
	dma_addr_t e_dma, n_dma, d_ref_dma, crt_ref_dma;
	int idx, ret;
	bool has_crt, is_sca;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.bits < PKE_RSA_MIN_BITS || req.bits > PKE_RSA_MAX_BITS)
		return -EINVAL;
	if (!req.e_len || req.e_len > PKE_MAX_OPERAND)
		return -EINVAL;
	if (req.flags & ~CMH_FLAG_MASK)
		return -EINVAL;

	n_len = req.bits / 8;
	has_crt = (req.crt_cid != 0);
	e_padded = ALIGN(req.e_len, 4);
	key_flags = req.flags & CMH_FLAG_MASK;
	is_sca = !!(req.flags & CMH_FLAG_SCA);

	/*
	 * SCA keys are stored in 2 shares -- DS allocation must be enlarged.
	 * CRI reference formulas: cmh_pke_rsa_private_key_size().
	 */
	if (is_sca) {
		d_ds_len = n_len * 2;
		crt_ds_len = (7 + n_len / 2) * 4;
	} else {
		d_ds_len = n_len;
		crt_ds_len = 5 * (n_len / 2);
	}

	e_buf = kzalloc(e_padded, GFP_KERNEL);
	n_buf = kzalloc(n_len, GFP_KERNEL);
	d_ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	crt_ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	if (!e_buf || !n_buf || !d_ref_buf || !crt_ref_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(e_buf + e_padded - req.e_len,
			   u64_to_user_ptr(req.e), req.e_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	e_dma = cmh_dma_map_single(e_buf, e_padded, DMA_TO_DEVICE);
	n_dma = cmh_dma_map_single(n_buf, n_len, DMA_FROM_DEVICE);
	d_ref_dma = cmh_dma_map_single(d_ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	crt_ref_dma = cmh_dma_map_single(crt_ref_buf, sizeof(u64),
					 DMA_FROM_DEVICE);
	if (cmh_dma_map_error(e_dma) || cmh_dma_map_error(n_dma) ||
	    cmh_dma_map_error(d_ref_dma) || cmh_dma_map_error(crt_ref_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	if (has_crt) {
		/*
		 * Two-VCQ approach (CRI pattern): SYS_REF_LAST can only
		 * refer to the most recently created DS object.  When we
		 * need both d and crt refs, we must first allocate DS
		 * objects, read back the opaque refs, then pass them by
		 * value in the keygen VCQ.
		 *
		 * VCQ #1: allocate both DS objects.
		 */
		idx = 0;
		vcq_set_header(&vcq[idx++], 4);
		vcq_add_sys_new(&vcq[idx++], req.d_cid, d_ref_dma, d_ds_len);
		vcq_add_sys_new(&vcq[idx++], req.crt_cid, crt_ref_dma,
				crt_ds_len);
		vcq_add_sys_flush(&vcq[idx++]);

		ret = cmh_tm_submit_sync_mbx(vcq, 4, 1, MGMT_MBX);
		if (ret)
			goto out_unmap;

		/* Sync DMA so we can read back the opaque refs */
		cmh_dma_unmap_single(d_ref_dma, sizeof(u64), DMA_FROM_DEVICE);
		cmh_dma_unmap_single(crt_ref_dma, sizeof(u64),
				     DMA_FROM_DEVICE);
		d_ref_dma = 0;
		crt_ref_dma = 0;

		/*
		 * VCQ #2: keygen with resolved refs.
		 */
		idx = 0;
		memset(vcq, 0, sizeof(vcq));
		vcq_set_header(&vcq[idx++], 4);

		vcq[idx].magic = VCQ_CMD_MAGIC;
		vcq[idx].id = VCQ_CMD_ID(pke_cid, PKE_SWAP_FLAGS, 1,
					 PKE_CMD_RSA_KEYGEN);
		vcq[idx].hwc.pke.cmd_rsa_keygen.bits = req.bits;
		vcq[idx].hwc.pke.cmd_rsa_keygen.e = e_dma;
		vcq[idx].hwc.pke.cmd_rsa_keygen.n = n_dma;
		vcq[idx].hwc.pke.cmd_rsa_keygen.d = *d_ref_buf;
		vcq[idx].hwc.pke.cmd_rsa_keygen.d_type =
			SYS_TYPE_SET(key_flags, CORE_ID_PKE);
		vcq[idx].hwc.pke.cmd_rsa_keygen.crt = *crt_ref_buf;
		vcq[idx].hwc.pke.cmd_rsa_keygen.crt_type =
			SYS_TYPE_SET(key_flags, CORE_ID_PKE);
		idx++;

		vcq_add_pke_flush(&vcq[idx++], pke_cid);
		vcq_add_sys_flush(&vcq[idx++]);

		ret = cmh_tm_submit_sync_tmo(vcq, 4, 1, MGMT_MBX,
					     cmh_tm_slow_op_timeout_jiffies());
	} else {
		/*
		 * Single-VCQ: only d, so SYS_REF_LAST is unambiguous.
		 */
		idx = 0;
		vcq_set_header(&vcq[idx++], 5);
		vcq_add_sys_new(&vcq[idx++], req.d_cid, d_ref_dma, d_ds_len);

		vcq[idx].magic = VCQ_CMD_MAGIC;
		vcq[idx].id = VCQ_CMD_ID(pke_cid, PKE_SWAP_FLAGS, 1,
					 PKE_CMD_RSA_KEYGEN);
		vcq[idx].hwc.pke.cmd_rsa_keygen.bits = req.bits;
		vcq[idx].hwc.pke.cmd_rsa_keygen.e = e_dma;
		vcq[idx].hwc.pke.cmd_rsa_keygen.n = n_dma;
		vcq[idx].hwc.pke.cmd_rsa_keygen.d = SYS_REF_LAST;
		vcq[idx].hwc.pke.cmd_rsa_keygen.d_type =
			SYS_TYPE_SET(key_flags, CORE_ID_PKE);
		vcq[idx].hwc.pke.cmd_rsa_keygen.crt = SYS_REF_NONE;
		vcq[idx].hwc.pke.cmd_rsa_keygen.crt_type = 0;
		idx++;

		vcq_add_pke_flush(&vcq[idx++], pke_cid);
		vcq_add_sys_flush(&vcq[idx++]);

		ret = cmh_tm_submit_sync_tmo(vcq, 5, 1, MGMT_MBX,
					     cmh_tm_slow_op_timeout_jiffies());
	}

out_unmap:
	if (crt_ref_dma && !cmh_dma_map_error(crt_ref_dma))
		cmh_dma_unmap_single(crt_ref_dma, sizeof(u64),
				     DMA_FROM_DEVICE);
	if (d_ref_dma && !cmh_dma_map_error(d_ref_dma))
		cmh_dma_unmap_single(d_ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(n_dma))
		cmh_dma_unmap_single(n_dma, n_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(e_dma))
		cmh_dma_unmap_single(e_dma, e_padded, DMA_TO_DEVICE);

	if (!ret) {
		/* Copy generated modulus and refs back */
		if (copy_to_user(u64_to_user_ptr(req.n), n_buf, n_len)) {
			ret = -EFAULT;
			goto out_free;
		}
		req.d_ref = *d_ref_buf;
		req.crt_ref = has_crt ? *crt_ref_buf : 0;
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

out_free:
	kfree(crt_ref_buf);
	kfree(d_ref_buf);
	kfree(n_buf);
	kfree(e_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_ecdsa_sign() - Handle CMH_MGMT_IOC_PKE_ECDSA_SIGN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_ecdsa_sign(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_ecdsa_sign req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 clen, sig_len, dig_map_len;
	u8 *dig_buf, *sig_buf;
	dma_addr_t dig_dma, sig_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	clen = cmh_pke_validate_curve(req.curve);
	if (!clen || !req.digest_len ||
	    req.digest_len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;

	sig_len = 2 * clen;

	/*
	 * eSW requires digest_len >= clen.  Zero-pad shorter hashes.
	 */
	dig_map_len = max_t(u32, req.digest_len, clen);

	dig_buf = kzalloc(dig_map_len, GFP_KERNEL);
	sig_buf = kzalloc(sig_len, GFP_KERNEL);
	if (!dig_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(dig_buf, u64_to_user_ptr(req.digest),
			   req.digest_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	dig_dma = cmh_dma_map_single(dig_buf, dig_map_len, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_buf, sig_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(dig_dma) || cmh_dma_map_error(sig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_ecdsa_sign(&vcq[1], pke_cid, req.curve, clen,
			       dig_dma, sig_dma, req.key_ref,
			       dig_map_len, pke_swap_flags(req.curve));
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(dig_dma))
		cmh_dma_unmap_single(dig_dma, dig_map_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.signature),
				 sig_buf, sig_len))
			ret = -EFAULT;
	}

out_free:
	kfree(sig_buf);
	kfree(dig_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_ecdh() - Handle CMH_MGMT_IOC_PKE_ECDH ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_ecdh(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_ecdh req;
	/* Phase 1: hdr + sys_new + pke_ecdh + pke_flush; reused for Phase 2 */
	struct vcq_cmd vcq[4];
	u32 clen, swap, ss_type;
	u8 *peer_buf, *ss_buf;
	u64 *ref_buf;
	dma_addr_t peer_dma, ss_dma, ref_dma;
	int ret, idx;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	clen = cmh_pke_validate_curve(req.curve);
	if (!clen)
		return -EINVAL;

	swap = PKE_SWAP_FLAGS;
	ss_type = SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_PKE);

	peer_buf = kmalloc(clen, GFP_KERNEL);
	ss_buf = kzalloc(clen, GFP_KERNEL);
	ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	if (!peer_buf || !ss_buf || !ref_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(peer_buf, u64_to_user_ptr(req.peer_key_x), clen)) {
		ret = -EFAULT;
		goto out_free;
	}

	peer_dma = cmh_dma_map_single(peer_buf, clen, DMA_TO_DEVICE);
	ss_dma = cmh_dma_map_single(ss_buf, clen, DMA_FROM_DEVICE);
	ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(peer_dma) || cmh_dma_map_error(ss_dma) ||
	    cmh_dma_map_error(ref_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	idx = 0;
	vcq_set_header(&vcq[idx++], 4);
	vcq_add_sys_new(&vcq[idx++], 0, ref_dma, clen);
	vcq_add_pke_ecdh(&vcq[idx++], pke_cid, req.curve, clen, clen,
			 ss_type, peer_dma, req.key_ref,
			 SYS_REF_LAST, swap);
	vcq_add_pke_flush(&vcq[idx++], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, 4, 1, MGMT_MBX);
	if (ret)
		goto out_unmap;

	/* Sync bounce buffer so CPU sees the DMA-written ref */
	cmh_dma_sync_for_cpu(ref_dma, sizeof(u64), DMA_FROM_DEVICE);

	/* Phase 2: extract shared secret from DS via actual ref */
	vcq_set_header(&vcq[0], 3);
	vcq_add_sys_data(&vcq[1], *ref_buf, ss_dma, clen);
	vcq[1].id |= pke_swap_flags(req.curve);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, 3, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(ref_dma))
		cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(ss_dma))
		cmh_dma_unmap_single(ss_dma, clen, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(peer_dma))
		cmh_dma_unmap_single(peer_dma, clen, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.output), ss_buf, clen))
			ret = -EFAULT;
	}

out_free:
	kfree(ref_buf);
	kfree_sensitive(ss_buf);
	kfree(peer_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_ecdh_keygen() - Handle CMH_MGMT_IOC_PKE_ECDH_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_ecdh_keygen(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_ecdh_keygen req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 clen, out_len;
	u8 *pkx_buf;
	dma_addr_t pkx_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	clen = cmh_pke_validate_curve(req.curve);
	if (!clen)
		return -EINVAL;

	/*
	 * ECDH_KEYGEN always outputs both X and Y coordinates
	 * (2 * clen bytes total) even though only X is useful for
	 * the ECDH exchange.  Allocate the full output size to avoid
	 * a DMA buffer overflow, but copy only X back to userspace.
	 */
	out_len = 2 * clen;

	pkx_buf = kzalloc(out_len, GFP_KERNEL);
	if (!pkx_buf)
		return -ENOMEM;

	pkx_dma = cmh_dma_map_single(pkx_buf, out_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(pkx_dma)) {
		kfree(pkx_buf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_ecdh_keygen(&vcq[1], pke_cid, req.curve, clen,
				pkx_dma, req.key_ref,
				PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

	cmh_dma_unmap_single(pkx_dma, out_len, DMA_FROM_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.public_key_x),
				 pkx_buf, clen))
			ret = -EFAULT;
	}

	kfree(pkx_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_eddsa_sign() - Handle CMH_MGMT_IOC_PKE_EDDSA_SIGN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_eddsa_sign(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_eddsa_sign req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 klen, sig_len;
	u8 *msg_buf, *sig_buf;
	dma_addr_t msg_dma, sig_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (!cmh_pke_validate_curve(req.curve) || !req.digest_len ||
	    req.digest_len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;
	if (!pke_curve_is_edwards(req.curve))
		return -EINVAL;

	klen = pke_eddsa_key_len(req.curve);
	sig_len = 2 * klen;

	msg_buf = kmalloc(req.digest_len, GFP_KERNEL);
	sig_buf = kzalloc(sig_len, GFP_KERNEL);
	if (!msg_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(msg_buf, u64_to_user_ptr(req.digest),
			   req.digest_len)) {
		ret = -EFAULT;
		goto out_free;
	}

	msg_dma = cmh_dma_map_single(msg_buf, req.digest_len, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_buf, sig_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(msg_dma) || cmh_dma_map_error(sig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_eddsa_sign(&vcq[1], pke_cid, req.curve, klen,
			       msg_dma, sig_dma, req.key_ref,
			       req.digest_len, pke_swap_flags(req.curve));
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(msg_dma))
		cmh_dma_unmap_single(msg_dma, req.digest_len, DMA_TO_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.signature),
				 sig_buf, sig_len))
			ret = -EFAULT;
	}

out_free:
	kfree(sig_buf);
	kfree(msg_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_eddsa_verify() - Handle CMH_MGMT_IOC_PKE_EDDSA_VERIFY ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_eddsa_verify(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_eddsa_verify req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 clen, klen, sig_len;
	u8 *msg_buf, *sig_buf, *pky_buf, *rp_buf;
	dma_addr_t msg_dma, sig_dma, pky_dma, rp_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	clen = cmh_pke_validate_curve(req.curve);
	if (!clen || !req.digest_len ||
	    req.digest_len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;
	if (!pke_curve_is_edwards(req.curve))
		return -EINVAL;

	klen = pke_eddsa_key_len(req.curve);
	sig_len = 2 * klen;

	msg_buf = kmalloc(req.digest_len, GFP_KERNEL);
	sig_buf = kmalloc(sig_len, GFP_KERNEL);
	pky_buf = kmalloc(klen, GFP_KERNEL);
	rp_buf = kzalloc(clen, GFP_KERNEL);
	if (!msg_buf || !sig_buf || !pky_buf || !rp_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(msg_buf, u64_to_user_ptr(req.digest),
			   req.digest_len) ||
	    copy_from_user(sig_buf, u64_to_user_ptr(req.signature),
			   sig_len) ||
	    copy_from_user(pky_buf, u64_to_user_ptr(req.public_key_y),
			   klen)) {
		ret = -EFAULT;
		goto out_free;
	}

	msg_dma = cmh_dma_map_single(msg_buf, req.digest_len, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_buf, sig_len, DMA_TO_DEVICE);
	pky_dma = cmh_dma_map_single(pky_buf, klen, DMA_TO_DEVICE);
	rp_dma = cmh_dma_map_single(rp_buf, clen, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(msg_dma) || cmh_dma_map_error(sig_dma) ||
	    cmh_dma_map_error(pky_dma) || cmh_dma_map_error(rp_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_eddsa_verify(&vcq[1], pke_cid, req.curve, req.digest_len,
				 pky_dma, msg_dma, sig_dma, rp_dma,
				 pke_swap_flags(req.curve));
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

out_unmap:
	if (!cmh_dma_map_error(rp_dma))
		cmh_dma_unmap_single(rp_dma, clen, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(pky_dma))
		cmh_dma_unmap_single(pky_dma, klen, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(msg_dma))
		cmh_dma_unmap_single(msg_dma, req.digest_len, DMA_TO_DEVICE);

out_free:
	kfree(rp_buf);
	kfree(pky_buf);
	kfree(sig_buf);
	kfree(msg_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_ec_keygen() - Handle CMH_MGMT_IOC_PKE_EC_KEYGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_ec_keygen(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_ec_keygen req;
	/* header + SYS_NEW + ECDSA_KEYGEN + flush_pke + flush_sys */
	struct vcq_cmd vcq[5];
	u32 clen, key_flags, ds_len;
	u64 *ref_buf;
	dma_addr_t ref_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (req.flags & ~CMH_FLAG_MASK)
		return -EINVAL;
	clen = cmh_pke_validate_curve(req.curve);
	if (!clen)
		return -EINVAL;

	key_flags = req.flags & CMH_FLAG_MASK;
	/* SCA keys are stored in 2 shares -- allocate double the curve length */
	ds_len = (req.flags & CMH_FLAG_SCA) ? clen * 2 : clen;

	ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	if (!ref_buf)
		return -ENOMEM;

	ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ref_dma)) {
		kfree(ref_buf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], 5);
	vcq_add_sys_new(&vcq[1], req.cid, ref_dma, ds_len);
	vcq_add_pke_ecdsa_keygen(&vcq[2], pke_cid, req.curve, clen,
				 SYS_REF_LAST,
				 SYS_TYPE_SET(key_flags, CORE_ID_PKE),
				 pke_swap_flags(req.curve));
	vcq_add_pke_flush(&vcq[3], pke_cid);
	vcq_add_sys_flush(&vcq[4]);

	ret = cmh_tm_submit_sync_mbx(vcq, 5, 1, MGMT_MBX);

	cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);

	if (!ret) {
		req.ref = *ref_buf;
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

	kfree(ref_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_ec_pubgen() - Handle CMH_MGMT_IOC_PKE_EC_PUBGEN ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_ec_pubgen(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_ec_pubgen req;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u32 clen, pk_len;
	u8 *pk_buf;
	dma_addr_t pk_dma;
	bool is_ed;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	clen = cmh_pke_validate_curve(req.curve);
	if (!clen)
		return -EINVAL;

	is_ed = pke_curve_is_edwards(req.curve);
	pk_len = is_ed ? pke_eddsa_key_len(req.curve) : 2 * clen;

	pk_buf = kzalloc(pk_len, GFP_KERNEL);
	if (!pk_buf)
		return -ENOMEM;

	pk_dma = cmh_dma_map_single(pk_buf, pk_len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(pk_dma)) {
		kfree(pk_buf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	if (is_ed)
		vcq_add_pke_eddsa_pubgen(&vcq[1], pke_cid, req.curve,
					 pke_eddsa_key_len(req.curve),
					 pk_dma, req.key_ref,
					 pke_swap_flags(req.curve));
	else
		vcq_add_pke_ecdsa_pubgen(&vcq[1], pke_cid, req.curve, clen,
					 pk_dma, req.key_ref,
					 pke_swap_flags(req.curve));
	vcq_add_pke_flush(&vcq[2], pke_cid);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, MGMT_MBX);

	cmh_dma_unmap_single(pk_dma, pk_len, DMA_FROM_DEVICE);

	if (!ret) {
		if (copy_to_user(u64_to_user_ptr(req.public_key),
				 pk_buf, pk_len))
			ret = -EFAULT;
	}

	kfree(pk_buf);
	return ret;
}

/**
 * cmh_mgmt_pke_eddsa_keygen_sca() - Handle CMH_MGMT_IOC_PKE_EDDSA_KEYGEN_SCA ioctl
 * @argp: User-space ioctl argument pointer
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_pke_eddsa_keygen_sca(void __user *argp)
{
	u32 pke_cid = cmh_core_default_id(CMH_CORE_PKE);

	struct cmh_ioctl_pke_eddsa_keygen_sca req;
	/* header + SYS_NEW + EDDSA_KEYGEN_SCA + flush_pke + flush_sys */
	struct vcq_cmd vcq[5];
	u64 *ref_buf;
	dma_addr_t ref_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	/* EdDSA SCA keygen is only supported for Ed448 */
	if (req.curve != PKE_CURVE_448)
		return -EINVAL;

	ref_buf = kzalloc_obj(u64, GFP_KERNEL);
	if (!ref_buf)
		return -ENOMEM;

	ref_dma = cmh_dma_map_single(ref_buf, sizeof(u64), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ref_dma)) {
		kfree(ref_buf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], 5);
	vcq_add_sys_new(&vcq[1], req.cid, ref_dma, PKE_ED448_SK_SCA_LEN);
	vcq_add_pke_eddsa_keygen_sca(&vcq[2], pke_cid, req.curve, req.key_ref,
				     SYS_REF_LAST);
	vcq_add_pke_flush(&vcq[3], pke_cid);
	vcq_add_sys_flush(&vcq[4]);

	ret = cmh_tm_submit_sync_mbx(vcq, 5, 1, MGMT_MBX);

	cmh_dma_unmap_single(ref_dma, sizeof(u64), DMA_FROM_DEVICE);

	if (!ret) {
		req.sca_ref = *ref_buf;
		if (copy_to_user(argp, &req, sizeof(req)))
			ret = -EFAULT;
	}

	kfree(ref_buf);
	return ret;
}
