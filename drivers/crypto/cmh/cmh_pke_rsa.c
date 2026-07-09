// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- RSA akcipher Driver
 *
 * Registers "rsa" akcipher algorithm with the Linux crypto subsystem
 * (priority 300, overrides software rsa-generic at 100).
 *
 * Raw RSA operations only (m^e mod n / c^d mod n).  The kernel's
 * pkcs1pad() template wraps this for PKCS#1 v1.5 / PSS / OAEP.
 *
 * Key format: DER-encoded ASN.1, parsed by kernel rsa_parse_pub_key()
 * / rsa_parse_priv_key() helpers.
 *
 * Private key via cmh_key_ctx: raw keys written via SYS_REF_TEMP.
 * Datastore-referenced keys are only reachable through the ioctl
 * path (cmh_mgmt.c).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <crypto/akcipher.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/rsa.h>

#include "cmh_pke.h"
#include "cmh_sys.h"
#include "cmh_sys_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

struct cmh_rsa_tfm_ctx {
	struct cmh_key_ctx key;		/* private key (raw d only) */
	u8 *n;				/* modulus (big-endian) */
	u8 *e;				/* public exponent (big-endian) */
	size_t n_sz;
	size_t e_sz;
	u32 bits;			/* key size in bits */
};

static inline struct cmh_rsa_tfm_ctx *cmh_rsa_ctx(struct crypto_akcipher *tfm)
{
	return akcipher_tfm_ctx(tfm);
}

struct cmh_rsa_reqctx {
	u8 *e_buf;
	u8 *n_buf;
	u8 *m_buf;
	u8 *c_buf;
	u8 *d_buf;		/* dec only: private key copy */
	dma_addr_t e_dma;
	dma_addr_t n_dma;
	dma_addr_t m_dma;
	dma_addr_t c_dma;
	dma_addr_t d_dma;
	u32 key_bytes;
	u32 e_padded;
	u32 n_sz;
	u32 d_len;		/* dec only */
};

static u32 cmh_rsa_key_bits(size_t n_sz)
{
	/*
	 * Only accept exact modulus sizes supported by the hardware.
	 * The programmed RSA width must match the actual modulus buffer
	 * length; rounding a shorter modulus up to the next size would
	 * let the device read past the end of the DMA buffer.
	 */
	switch (n_sz) {
	case 64:
		return 512;
	case 128:
		return 1024;
	case 256:
		return 2048;
	case 384:
		return 3072;
	case 512:
		return 4096;
	default:
		return 0;
	}
}

static void cmh_rsa_enc_complete(void *data, int error)
{
	struct akcipher_request *req = data;
	struct cmh_rsa_reqctx *rctx = akcipher_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (!cmh_dma_map_error(rctx->c_dma))
		cmh_dma_unmap_single(rctx->c_dma, rctx->key_bytes,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->m_dma))
		cmh_dma_unmap_single(rctx->m_dma, rctx->key_bytes,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->n_dma))
		cmh_dma_unmap_single(rctx->n_dma, rctx->n_sz,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->e_dma))
		cmh_dma_unmap_single(rctx->e_dma, rctx->e_padded,
				     DMA_TO_DEVICE);

	if (!error) {
		int nents;

		nents = sg_nents_for_len(req->dst, rctx->key_bytes);
		if (nents < 0 ||
		    sg_copy_from_buffer(req->dst, nents,
					rctx->c_buf,
					rctx->key_bytes) != rctx->key_bytes)
			error = -EINVAL;
		else
			req->dst_len = rctx->key_bytes;
	}

	kfree(rctx->c_buf);
	rctx->c_buf = NULL;
	kfree_sensitive(rctx->m_buf);
	rctx->m_buf = NULL;
	kfree(rctx->n_buf);
	rctx->n_buf = NULL;
	kfree(rctx->e_buf);
	rctx->e_buf = NULL;
	cmh_complete(&req->base, error);
}

/*
 * RSA encrypt: c = m^e mod n (public key operation)
 * Also used for signature verification (verify = encrypt for raw RSA).
 */
static int cmh_rsa_enc(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);
	struct cmh_rsa_reqctx *rctx = akcipher_request_ctx(req);
	u32 key_bytes = ctx->bits / 8;
	u32 e_padded = ALIGN(ctx->e_sz, 4);
	struct core_dispatch d = cmh_core_select_instance(CMH_CORE_PKE);
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	int ret, nents;
	gfp_t gfp;

	if (!ctx->n || !ctx->e)
		return -EINVAL;
	if (req->src_len > key_bytes || req->dst_len < key_bytes)
		return -EINVAL;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->key_bytes = key_bytes;
	rctx->e_padded = e_padded;
	rctx->n_sz = ctx->n_sz;
	rctx->e_dma = DMA_MAPPING_ERROR;
	rctx->n_dma = DMA_MAPPING_ERROR;
	rctx->m_dma = DMA_MAPPING_ERROR;
	rctx->c_dma = DMA_MAPPING_ERROR;

	rctx->e_buf = kzalloc(e_padded, gfp);
	rctx->n_buf = kmemdup(ctx->n, ctx->n_sz, gfp);
	rctx->m_buf = kzalloc(key_bytes, gfp);
	rctx->c_buf = kzalloc(key_bytes, gfp);
	if (!rctx->e_buf || !rctx->n_buf || !rctx->m_buf || !rctx->c_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	memcpy(rctx->e_buf + e_padded - ctx->e_sz, ctx->e, ctx->e_sz);

	nents = sg_nents_for_len(req->src, req->src_len);
	if (nents < 0 ||
	    sg_pcopy_to_buffer(req->src, nents,
			       rctx->m_buf + key_bytes - req->src_len,
			       req->src_len, 0) != req->src_len) {
		ret = -EINVAL;
		goto out_free;
	}

	rctx->e_dma = cmh_dma_map_single(rctx->e_buf, e_padded,
					 DMA_TO_DEVICE);
	rctx->n_dma = cmh_dma_map_single(rctx->n_buf, ctx->n_sz,
					 DMA_TO_DEVICE);
	rctx->m_dma = cmh_dma_map_single(rctx->m_buf, key_bytes,
					 DMA_TO_DEVICE);
	rctx->c_dma = cmh_dma_map_single(rctx->c_buf, key_bytes,
					 DMA_FROM_DEVICE);

	if (cmh_dma_map_error(rctx->e_dma) ||
	    cmh_dma_map_error(rctx->n_dma) ||
	    cmh_dma_map_error(rctx->m_dma) ||
	    cmh_dma_map_error(rctx->c_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_rsa_enc(&vcq[1], d.core_id, ctx->bits, e_padded,
			    rctx->e_dma, rctx->n_dma, rctx->m_dma,
			    rctx->c_dma, PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[2], d.core_id);

	ret = cmh_tm_submit_async(vcq, PKE_VCQ_CMDS_MIN, 1, d.mbx_idx,
				  cmh_rsa_enc_complete, req,
				  !!(req->base.flags &
				     CRYPTO_TFM_REQ_MAY_BACKLOG), 0);
	if (ret == -EBUSY)
		return -EBUSY;
	if (!ret)
		return -EINPROGRESS;

out_unmap:
	if (!cmh_dma_map_error(rctx->c_dma))
		cmh_dma_unmap_single(rctx->c_dma, key_bytes,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->m_dma))
		cmh_dma_unmap_single(rctx->m_dma, key_bytes,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->n_dma))
		cmh_dma_unmap_single(rctx->n_dma, ctx->n_sz,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->e_dma))
		cmh_dma_unmap_single(rctx->e_dma, e_padded,
				     DMA_TO_DEVICE);

out_free:
	kfree(rctx->c_buf);
	kfree_sensitive(rctx->m_buf);
	kfree(rctx->n_buf);
	kfree(rctx->e_buf);
	return ret;
}

static void cmh_rsa_dec_complete(void *data, int error)
{
	struct akcipher_request *req = data;
	struct cmh_rsa_reqctx *rctx = akcipher_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (!cmh_dma_map_error(rctx->d_dma))
		cmh_dma_unmap_single(rctx->d_dma, rctx->d_len,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->m_dma))
		cmh_dma_unmap_single(rctx->m_dma, rctx->key_bytes,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->c_dma))
		cmh_dma_unmap_single(rctx->c_dma, rctx->key_bytes,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->n_dma))
		cmh_dma_unmap_single(rctx->n_dma, rctx->n_sz,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->e_dma))
		cmh_dma_unmap_single(rctx->e_dma, rctx->e_padded,
				     DMA_TO_DEVICE);

	if (!error) {
		int nents;

		nents = sg_nents_for_len(req->dst, rctx->key_bytes);
		if (nents < 0 ||
		    sg_copy_from_buffer(req->dst, nents,
					rctx->m_buf,
					rctx->key_bytes) != rctx->key_bytes)
			error = -EINVAL;
		else
			req->dst_len = rctx->key_bytes;
	}

	kfree_sensitive(rctx->d_buf);
	rctx->d_buf = NULL;
	kfree_sensitive(rctx->m_buf);
	rctx->m_buf = NULL;
	kfree(rctx->c_buf);
	rctx->c_buf = NULL;
	kfree(rctx->n_buf);
	rctx->n_buf = NULL;
	kfree(rctx->e_buf);
	rctx->e_buf = NULL;
	cmh_complete(&req->base, error);
}

/*
 * RSA decrypt: m = c^d mod n (private key operation)
 * Also used for signing (sign = decrypt for raw RSA).
 *
 * Private key 'd' is written via SYS_REF_TEMP inline.
 */
static int cmh_rsa_dec(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);
	struct cmh_rsa_reqctx *rctx = akcipher_request_ctx(req);
	u32 key_bytes = ctx->bits / 8;
	u32 e_padded = ALIGN(ctx->e_sz, 4);
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MAX];
	struct core_dispatch dd;
	int ret, idx, nents;
	gfp_t gfp;

	if (ctx->key.mode != CMH_KEY_RAW)
		return -EINVAL;
	if (!ctx->n || !ctx->e)
		return -EINVAL;
	if (req->src_len > key_bytes || req->dst_len < key_bytes)
		return -EINVAL;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->key_bytes = key_bytes;
	rctx->e_padded = e_padded;
	rctx->n_sz = ctx->n_sz;
	rctx->e_dma = DMA_MAPPING_ERROR;
	rctx->n_dma = DMA_MAPPING_ERROR;
	rctx->m_dma = DMA_MAPPING_ERROR;
	rctx->c_dma = DMA_MAPPING_ERROR;
	rctx->d_dma = DMA_MAPPING_ERROR;

	rctx->e_buf = kzalloc(e_padded, gfp);
	rctx->n_buf = kmemdup(ctx->n, ctx->n_sz, gfp);
	rctx->c_buf = kzalloc(key_bytes, gfp);
	rctx->m_buf = kzalloc(key_bytes, gfp);
	if (!rctx->e_buf || !rctx->n_buf || !rctx->c_buf || !rctx->m_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	memcpy(rctx->e_buf + e_padded - ctx->e_sz, ctx->e, ctx->e_sz);

	nents = sg_nents_for_len(req->src, req->src_len);
	if (nents < 0 ||
	    sg_pcopy_to_buffer(req->src, nents,
			       rctx->c_buf + key_bytes - req->src_len,
			       req->src_len, 0) != req->src_len) {
		ret = -EINVAL;
		goto out_free;
	}

	rctx->e_dma = cmh_dma_map_single(rctx->e_buf, e_padded,
					 DMA_TO_DEVICE);
	rctx->n_dma = cmh_dma_map_single(rctx->n_buf, ctx->n_sz,
					 DMA_TO_DEVICE);
	rctx->c_dma = cmh_dma_map_single(rctx->c_buf, key_bytes,
					 DMA_TO_DEVICE);
	rctx->m_dma = cmh_dma_map_single(rctx->m_buf, key_bytes,
					 DMA_FROM_DEVICE);

	if (cmh_dma_map_error(rctx->e_dma) ||
	    cmh_dma_map_error(rctx->n_dma) ||
	    cmh_dma_map_error(rctx->c_dma) ||
	    cmh_dma_map_error(rctx->m_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	dd = cmh_core_select_instance(CMH_CORE_PKE);

	rctx->d_buf = kmemdup(ctx->key.raw.data, ctx->key.raw.len, gfp);
	if (!rctx->d_buf) {
		ret = -ENOMEM;
		goto out_unmap;
	}
	rctx->d_len = ctx->key.raw.len;

	rctx->d_dma = cmh_dma_map_single(rctx->d_buf, ctx->key.raw.len,
					 DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->d_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	idx = 1;
	vcq_add_sys_write(&vcq[idx], SYS_REF_TEMP, rctx->d_dma,
			  SYS_REF_NONE, ctx->key.raw.len,
			  ctx->key.raw.sys_type);
	vcq[idx].id |= PKE_SWAP_FLAGS;
	idx++;
	vcq_add_pke_rsa_dec(&vcq[idx++], dd.core_id, ctx->bits, e_padded,
			    rctx->e_dma, rctx->n_dma, rctx->c_dma,
			    rctx->m_dma, SYS_REF_TEMP, PKE_SWAP_FLAGS);
	vcq_add_pke_flush(&vcq[idx++], dd.core_id);
	vcq_set_header(&vcq[0], idx);

	ret = cmh_tm_submit_async(vcq, idx, 1, dd.mbx_idx,
				  cmh_rsa_dec_complete, req,
				  !!(req->base.flags &
				     CRYPTO_TFM_REQ_MAY_BACKLOG), 0);
	if (ret == -EBUSY)
		return -EBUSY;
	if (!ret)
		return -EINPROGRESS;

out_unmap:
	if (!cmh_dma_map_error(rctx->d_dma))
		cmh_dma_unmap_single(rctx->d_dma, rctx->d_len,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->m_dma))
		cmh_dma_unmap_single(rctx->m_dma, key_bytes,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->c_dma))
		cmh_dma_unmap_single(rctx->c_dma, key_bytes,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->n_dma))
		cmh_dma_unmap_single(rctx->n_dma, ctx->n_sz,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->e_dma))
		cmh_dma_unmap_single(rctx->e_dma, e_padded,
				     DMA_TO_DEVICE);

out_free:
	kfree_sensitive(rctx->d_buf);
	kfree_sensitive(rctx->m_buf);
	kfree(rctx->c_buf);
	kfree(rctx->n_buf);
	kfree(rctx->e_buf);
	return ret;
}

static int cmh_rsa_set_pub_key(struct crypto_akcipher *tfm,
			       const void *key, unsigned int keylen)
{
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);
	struct rsa_key rsa = {};
	int ret;

	ret = rsa_parse_pub_key(&rsa, key, keylen);
	if (ret)
		return ret;

	/* Strip ASN.1 leading zero padding from modulus */
	while (rsa.n_sz > 0 && rsa.n[0] == 0) {
		rsa.n++;
		rsa.n_sz--;
	}

	ctx->bits = cmh_rsa_key_bits(rsa.n_sz);
	if (!ctx->bits)
		return -EINVAL;

	kfree(ctx->n);
	kfree(ctx->e);
	ctx->n = NULL;
	ctx->e = NULL;
	ctx->n_sz = 0;
	ctx->e_sz = 0;

	ctx->n = kmemdup(rsa.n, rsa.n_sz, GFP_KERNEL);
	ctx->e = kmemdup(rsa.e, rsa.e_sz, GFP_KERNEL);
	if (!ctx->n || !ctx->e) {
		kfree(ctx->n);
		kfree(ctx->e);
		ctx->n = NULL;
		ctx->e = NULL;
		return -ENOMEM;
	}

	ctx->n_sz = rsa.n_sz;
	ctx->e_sz = rsa.e_sz;

	return 0;
}

static int cmh_rsa_set_priv_key(struct crypto_akcipher *tfm,
				const void *key, unsigned int keylen)
{
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);
	struct rsa_key rsa = {};
	u32 key_bytes;
	u8 *d_padded;
	int ret;

	ret = rsa_parse_priv_key(&rsa, key, keylen);
	if (ret)
		return ret;

	/* Strip ASN.1 leading zero padding from modulus */
	while (rsa.n_sz > 0 && rsa.n[0] == 0) {
		rsa.n++;
		rsa.n_sz--;
	}

	ctx->bits = cmh_rsa_key_bits(rsa.n_sz);
	if (!ctx->bits || !rsa.d_sz)
		return -EINVAL;

	key_bytes = ctx->bits / 8;

	/* Strip ASN.1 leading zero padding from private exponent */
	while (rsa.d_sz > 0 && rsa.d[0] == 0) {
		rsa.d++;
		rsa.d_sz--;
	}

	if (!rsa.d_sz || rsa.d_sz > key_bytes)
		return -EINVAL;

	kfree(ctx->n);
	kfree(ctx->e);
	ctx->n = NULL;
	ctx->e = NULL;
	ctx->n_sz = 0;
	ctx->e_sz = 0;

	ctx->n = kmemdup(rsa.n, rsa.n_sz, GFP_KERNEL);
	ctx->e = kmemdup(rsa.e, rsa.e_sz, GFP_KERNEL);
	if (!ctx->n || !ctx->e) {
		ret = -ENOMEM;
		goto err;
	}

	ctx->n_sz = rsa.n_sz;
	ctx->e_sz = rsa.e_sz;

	/*
	 * Left-pad d to key_bytes (big-endian alignment).
	 * The CMH eSW resolves SYS_REF_TEMP by checking
	 * hdr->len >= key_bytes, so the written buffer must
	 * be at least key_bytes wide.
	 */
	d_padded = kzalloc(key_bytes, GFP_KERNEL);
	if (!d_padded) {
		ret = -ENOMEM;
		goto err;
	}
	memcpy(d_padded + key_bytes - rsa.d_sz, rsa.d, rsa.d_sz);

	ret = cmh_key_setkey_raw(&ctx->key, d_padded, key_bytes,
				 CORE_ID_PKE);
	kfree_sensitive(d_padded);
	if (ret)
		goto err;

	return 0;
err:
	kfree(ctx->n);
	kfree(ctx->e);
	ctx->n = NULL;
	ctx->e = NULL;
	ctx->n_sz = 0;
	ctx->e_sz = 0;
	ctx->bits = 0;
	return ret;
}

static unsigned int cmh_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);

	return ctx->n_sz;
}

static int cmh_rsa_init_tfm(struct crypto_akcipher *tfm)
{
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	tfm->reqsize = sizeof(struct cmh_rsa_reqctx);
	return 0;
}

static void cmh_rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct cmh_rsa_tfm_ctx *ctx = cmh_rsa_ctx(tfm);

	cmh_key_destroy(&ctx->key);
	kfree(ctx->n);
	kfree(ctx->e);
	ctx->n = NULL;
	ctx->e = NULL;
}

/*
 * Raw RSA stays as akcipher (encrypt/decrypt only).  The kernel's
 * rsassa-pkcs1 sig template wraps our akcipher for sign/verify,
 * matching the upstream split (rsa.c = akcipher,
 * rsassa-pkcs1.c = sig template).
 */
static struct akcipher_alg cmh_rsa_alg = {
	.encrypt	= cmh_rsa_enc,
	.decrypt	= cmh_rsa_dec,
	.set_pub_key	= cmh_rsa_set_pub_key,
	.set_priv_key	= cmh_rsa_set_priv_key,
	.max_size	= cmh_rsa_max_size,
	.init		= cmh_rsa_init_tfm,
	.exit		= cmh_rsa_exit_tfm,
	.base = {
		.cra_name	  = "rsa",
		.cra_driver_name  = "cri-cmh-rsa",
		.cra_priority	  = 300,
		.cra_flags	  = CRYPTO_ALG_ASYNC,
		.cra_module	  = THIS_MODULE,
		.cra_ctxsize	  = sizeof(struct cmh_rsa_tfm_ctx),
	},
};

static bool cmh_rsa_registered;

/**
 * cmh_pke_rsa_register() - Register RSA akcipher algorithm with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_pke_rsa_register(void)
{
	int ret;

	ret = crypto_register_akcipher(&cmh_rsa_alg);
	if (ret) {
		dev_err(cmh_dev(),
			"cmh: failed to register rsa akcipher (%d)\n",
			ret);
		return ret;
	}

	cmh_rsa_registered = true;
	return 0;
}

/**
 * cmh_pke_rsa_unregister() - Unregister RSA akcipher algorithm from the crypto framework
 */
void cmh_pke_rsa_unregister(void)
{
	if (cmh_rsa_registered)
		crypto_unregister_akcipher(&cmh_rsa_alg);
	cmh_rsa_registered = false;
}
