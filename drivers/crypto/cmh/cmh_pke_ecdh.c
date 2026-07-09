// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- ECDH / X25519 kpp Driver
 *
 * Registers "ecdh-nist-p256", "ecdh-nist-p384", and "curve25519"
 * kpp algorithms with priority 300.
 *
 * - set_secret: decodes private key from kpp_secret + ecdh struct
 *   (NIST curves) or raw 32-byte scalar (Curve25519).
 *   Stores in cmh_key_ctx: raw keys written via SYS_REF_TEMP.
 *   Datastore-referenced keys are only reachable through the ioctl
 *   path (cmh_mgmt.c).
 *
 * - generate_public_key: PKE_CMD_ECDH_KEYGEN -> outputs X coordinate
 *   (NIST Weierstrass) or full public key (Edwards/Montgomery).
 *   For NIST curves, we generate X||Y by calling ECDSA_PUBGEN instead,
 *   matching the kernel ecdh.c pattern that outputs uncompressed X||Y.
 *
 * - compute_shared_secret: PKE_CMD_ECDH -> shared secret X coordinate.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/internal/kpp.h>
#include <crypto/internal/ecc.h>

#include "cmh_pke.h"
#include "cmh_sys.h"
#include "cmh_sys_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/*
 * ECDH key format: kpp_secret header + key_size(u16) + key data.
 * We decode this inline to avoid depending on CONFIG_CRYPTO_ECDH.
 */
#define ECDH_KPP_SECRET_MIN_SIZE (sizeof(struct kpp_secret) + sizeof(unsigned short))

struct cmh_ecdh_tfm_ctx {
	struct cmh_key_ctx key;
	u32 curve;		/* PKE_CURVE_* */
	u32 clen;		/* coordinate length in bytes */
};

static inline struct cmh_ecdh_tfm_ctx *cmh_ecdh_ctx(struct crypto_kpp *tfm)
{
	return kpp_tfm_ctx(tfm);
}

/*
 * Per-request context for ECDH/X25519 operations.
 *
 * generate_public_key: single-phase async VCQ.
 * compute_shared_secret: 2-phase async VCQ with callback chaining.
 *   Phase 1: sys_write(sk) + sys_new(ref) + ecdh(peer) + pflush
 *            -> phase1 callback reads ref, submits Phase 2.
 *   Phase 2: sys_data(ref, ss_dma) + sys_flush
 *            -> phase2 callback extracts shared secret, completes req.
 *
 * Both phases target the same mbx_idx so the DS reference remains
 * valid, since DS objects are MBX-scoped.
 */
struct cmh_ecdh_reqctx {
	/* Buffers */
	u8 *pk_buf;		/* keygen: output public key */
	u8 *sk_buf;		/* private key copy */
	u8 *peer_buf;		/* compute: peer public key */
	u8 *ss_buf;		/* compute: shared secret output */
	u64 *ref_buf;		/* compute: DS ref from Phase 1 */
	/* DMA handles */
	dma_addr_t pk_dma;
	dma_addr_t sk_dma;
	dma_addr_t peer_dma;
	dma_addr_t ss_dma;
	dma_addr_t ref_dma;
	/* Sizes and params for Phase 2 re-submit */
	u32 out_len;		/* keygen: public key size */
	u32 clen;
	u32 peer_len;
	u32 sk_len;
	u32 dma_swap;
	int mbx_idx;		/* pinned MBX for Phase 2 */
};

/*
 * set_secret: NIST curves decode kpp_secret + u16 key_size + raw scalar.
 * Curve25519 uses raw 32-byte scalar directly.
 */
static int cmh_ecdh_set_secret_nist(struct crypto_kpp *tfm,
				    const void *buf, unsigned int len)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);
	const u8 *ptr = buf;
	struct kpp_secret secret;
	unsigned short key_size;
	int ret;

	if (!buf || len < ECDH_KPP_SECRET_MIN_SIZE)
		return -EINVAL;

	memcpy(&secret, ptr, sizeof(secret));
	ptr += sizeof(secret);

	if (secret.type != CRYPTO_KPP_SECRET_TYPE_ECDH)
		return -EINVAL;
	if (len < secret.len)
		return -EINVAL;

	memcpy(&key_size, ptr, sizeof(key_size));
	ptr += sizeof(key_size);

	if (key_size == 0) {
		/*
		 * key_size == 0: generate a validated random private key.
		 * Uses the kernel ECC library (FIPS 186-5 A.2.2) to ensure
		 * the scalar is in the valid range [2, n-3] for the curve.
		 */
		u64 priv[ECC_MAX_DIGITS];
		unsigned int ndigits = ctx->clen / sizeof(u64);
		unsigned int curve_id;
		u8 *rnd;

		if (secret.len != ECDH_KPP_SECRET_MIN_SIZE)
			return -EINVAL;
		if (ndigits > ECC_MAX_DIGITS)
			return -EINVAL;
		/* Reject non-limb-aligned clen to prevent ndigits truncation */
		if (ctx->clen % sizeof(u64))
			return -EINVAL;

		if (ctx->curve == PKE_CURVE_P256)
			curve_id = ECC_CURVE_NIST_P256;
		else if (ctx->curve == PKE_CURVE_P384)
			curve_id = ECC_CURVE_NIST_P384;
		else
			return -EINVAL;

		ret = ecc_gen_privkey(curve_id, ndigits, priv);
		if (ret) {
			memzero_explicit(priv, sizeof(priv));
			return ret;
		}

		rnd = kmalloc(ctx->clen, GFP_KERNEL);
		if (!rnd) {
			memzero_explicit(priv, sizeof(priv));
			return -ENOMEM;
		}

		/* Convert VLI (native LE-digit-order) to big-endian bytes */
		ecc_swap_digits(priv, (u64 *)rnd, ndigits);
		memzero_explicit(priv, sizeof(priv));

		ret = cmh_key_setkey_raw(&ctx->key, rnd, ctx->clen,
					 CORE_ID_PKE);
		kfree_sensitive(rnd);
		return ret;
	}

	if (key_size != ctx->clen)
		return -EINVAL;

	if (secret.len != ECDH_KPP_SECRET_MIN_SIZE + key_size)
		return -EINVAL;

	return cmh_key_setkey_raw(&ctx->key, ptr, key_size, CORE_ID_PKE);
}

static int cmh_ecdh_set_secret_x25519(struct crypto_kpp *tfm,
				      const void *buf, unsigned int len)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);

	if (len != pke_curve_clen(PKE_CURVE_25519))
		return -EINVAL;

	return cmh_key_setkey_raw(&ctx->key, buf, len, CORE_ID_PKE);
}

static void cmh_ecdh_keygen_complete(void *data, int error)
{
	struct kpp_request *req = data;
	struct cmh_ecdh_reqctx *rctx = kpp_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (!cmh_dma_map_error(rctx->sk_dma))
		cmh_dma_unmap_single(rctx->sk_dma, rctx->sk_len,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->pk_dma))
		cmh_dma_unmap_single(rctx->pk_dma, rctx->out_len,
				     DMA_FROM_DEVICE);

	if (!error) {
		int nents;

		nents = sg_nents_for_len(req->dst, rctx->out_len);
		if (nents < 0 ||
		    sg_copy_from_buffer(req->dst, nents,
					rctx->pk_buf,
					rctx->out_len) != rctx->out_len)
			error = -EINVAL;
		else
			req->dst_len = rctx->out_len;
	}

	kfree_sensitive(rctx->sk_buf);
	rctx->sk_buf = NULL;
	kfree(rctx->pk_buf);
	rctx->pk_buf = NULL;
	cmh_complete(&req->base, error);
}

/*
 * generate_public_key: For NIST ECDH, use ECDH_KEYGEN which outputs
 * the public key X-coordinate.  But the kernel kpp interface expects
 * uncompressed X||Y, so we use ECDSA_PUBGEN which gives us (X,Y).
 * For Curve25519, ECDH_KEYGEN gives us the Montgomery u-coordinate
 * which is the full public key.
 */
static int cmh_ecdh_generate_public_key(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);
	struct cmh_ecdh_reqctx *rctx = kpp_request_ctx(req);
	u32 clen = ctx->clen;
	bool is_25519 = (ctx->curve == PKE_CURVE_25519);
	u32 out_len = is_25519 ? clen : 2 * clen;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MAX];
	struct core_dispatch dd;
	u32 swap, dma_swap;
	int ret, idx;
	gfp_t gfp;

	if (ctx->key.mode != CMH_KEY_RAW)
		return -EINVAL;
	if (req->dst_len < out_len)
		return -EINVAL;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->out_len = out_len;
	rctx->sk_len = ctx->key.raw.len;
	rctx->pk_dma = DMA_MAPPING_ERROR;
	rctx->sk_dma = DMA_MAPPING_ERROR;

	rctx->pk_buf = kzalloc(out_len, gfp);
	if (!rctx->pk_buf)
		return -ENOMEM;

	rctx->pk_dma = cmh_dma_map_single(rctx->pk_buf, out_len,
					  DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->pk_dma)) {
		ret = -ENOMEM;
		goto out_free;
	}

	swap = PKE_SWAP_FLAGS;
	dma_swap = pke_swap_flags(ctx->curve);

	dd = cmh_core_select_instance(CMH_CORE_PKE);

	rctx->sk_buf = kmemdup(ctx->key.raw.data, ctx->key.raw.len, gfp);
	if (!rctx->sk_buf) {
		ret = -ENOMEM;
		goto out_unmap;
	}
	rctx->sk_dma = cmh_dma_map_single(rctx->sk_buf, ctx->key.raw.len,
					  DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->sk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MAX);
	idx = 1;
	vcq_add_sys_write(&vcq[idx], SYS_REF_TEMP, rctx->sk_dma,
			  SYS_REF_NONE, ctx->key.raw.len,
			  ctx->key.raw.sys_type);
	vcq[idx].id |= dma_swap;
	idx++;
	if (is_25519)
		vcq_add_pke_ecdh_keygen(&vcq[idx++], dd.core_id, ctx->curve,
					clen, rctx->pk_dma, SYS_REF_TEMP,
					swap);
	else
		vcq_add_pke_ecdsa_pubgen(&vcq[idx++], dd.core_id,
					 ctx->curve, clen, rctx->pk_dma,
					 SYS_REF_TEMP, swap);
	vcq_add_pke_flush(&vcq[idx++], dd.core_id);

	ret = cmh_tm_submit_async(vcq, PKE_VCQ_CMDS_MAX, 1, dd.mbx_idx,
				  cmh_ecdh_keygen_complete, req,
				  !!(req->base.flags &
				     CRYPTO_TFM_REQ_MAY_BACKLOG), 0);
	if (ret == -EBUSY)
		return -EBUSY;
	if (!ret)
		return -EINPROGRESS;

out_unmap:
	if (!cmh_dma_map_error(rctx->sk_dma))
		cmh_dma_unmap_single(rctx->sk_dma, ctx->key.raw.len,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->pk_dma))
		cmh_dma_unmap_single(rctx->pk_dma, out_len,
				     DMA_FROM_DEVICE);

out_free:
	kfree_sensitive(rctx->sk_buf);
	kfree(rctx->pk_buf);
	return ret;
}

static void cmh_ecdh_ss_phase2_complete(void *data, int error)
{
	struct kpp_request *req = data;
	struct cmh_ecdh_reqctx *rctx = kpp_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (!cmh_dma_map_error(rctx->ss_dma))
		cmh_dma_unmap_single(rctx->ss_dma, rctx->clen,
				     DMA_FROM_DEVICE);

	if (!error) {
		int nents;

		nents = sg_nents_for_len(req->dst, rctx->clen);
		if (nents < 0 ||
		    sg_copy_from_buffer(req->dst, nents,
					rctx->ss_buf,
					rctx->clen) != rctx->clen)
			error = -EINVAL;
		else
			req->dst_len = rctx->clen;
	}

	kfree(rctx->ref_buf);
	rctx->ref_buf = NULL;
	kfree_sensitive(rctx->ss_buf);
	rctx->ss_buf = NULL;
	cmh_complete(&req->base, error);
}

static void cmh_ecdh_ss_phase1_complete(void *data, int error)
{
	struct kpp_request *req = data;
	struct cmh_ecdh_reqctx *rctx = kpp_request_ctx(req);
	struct vcq_cmd vcq[3];
	int ret;

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	/* Phase 1-only resources: sk, peer -- always clean up */
	if (!cmh_dma_map_error(rctx->sk_dma))
		cmh_dma_unmap_single(rctx->sk_dma, rctx->sk_len,
				     DMA_TO_DEVICE);
	kfree_sensitive(rctx->sk_buf);
	rctx->sk_buf = NULL;

	if (!cmh_dma_map_error(rctx->peer_dma))
		cmh_dma_unmap_single(rctx->peer_dma, rctx->peer_len,
				     DMA_TO_DEVICE);
	kfree(rctx->peer_buf);
	rctx->peer_buf = NULL;

	if (error)
		goto out_cleanup;

	/* Read the DS reference written by Phase 1 */
	cmh_dma_sync_for_cpu(rctx->ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	cmh_dma_unmap_single(rctx->ref_dma, sizeof(u64), DMA_FROM_DEVICE);
	rctx->ref_dma = DMA_MAPPING_ERROR;

	/* Phase 2: extract shared secret from DS */
	vcq_set_header(&vcq[0], 3);
	vcq_add_sys_data(&vcq[1], *rctx->ref_buf, rctx->ss_dma,
			 rctx->clen);
	vcq[1].id |= rctx->dma_swap;
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_async(vcq, 3, 1, rctx->mbx_idx,
				  cmh_ecdh_ss_phase2_complete, req,
				  true, 0);
	if (ret == -EBUSY || !ret)
		return;

	error = ret;

out_cleanup:
	if (!cmh_dma_map_error(rctx->ref_dma))
		cmh_dma_unmap_single(rctx->ref_dma, sizeof(u64),
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->ss_dma))
		cmh_dma_unmap_single(rctx->ss_dma, rctx->clen,
				     DMA_FROM_DEVICE);
	kfree(rctx->ref_buf);
	rctx->ref_buf = NULL;
	kfree_sensitive(rctx->ss_buf);
	rctx->ss_buf = NULL;
	cmh_complete(&req->base, error);
}

/*
 * compute_shared_secret: PKE_CMD_ECDH.
 *
 * req->src = peer public key (X||Y for NIST, raw 32B for Curve25519).
 * Output = shared secret X coordinate (clen bytes).
 *
 * The CMH ECDH command stores the shared secret in a DS object,
 * not directly to DMA.  We create a DS slot with SYS_CMD_NEW,
 * reference it via SYS_REF_LAST, then extract the result with a
 * second VCQ submission using SYS_CMD_DATA with the actual ref.
 */
static int cmh_ecdh_compute_shared_secret(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);
	struct cmh_ecdh_reqctx *rctx = kpp_request_ctx(req);
	u32 clen = ctx->clen;
	bool is_25519 = (ctx->curve == PKE_CURVE_25519);
	u32 peer_len = is_25519 ? clen : 2 * clen;
	u32 ss_type = SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_PKE);
	struct vcq_cmd vcq[5];
	struct core_dispatch dd;
	u32 swap, dma_swap;
	int ret, idx, nents;
	gfp_t gfp;

	if (ctx->key.mode != CMH_KEY_RAW)
		return -EINVAL;
	if (req->src_len < peer_len || req->dst_len < clen)
		return -EINVAL;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->clen = clen;
	rctx->peer_len = peer_len;
	rctx->sk_len = ctx->key.raw.len;
	rctx->pk_dma = DMA_MAPPING_ERROR;
	rctx->sk_dma = DMA_MAPPING_ERROR;
	rctx->peer_dma = DMA_MAPPING_ERROR;
	rctx->ss_dma = DMA_MAPPING_ERROR;
	rctx->ref_dma = DMA_MAPPING_ERROR;

	rctx->peer_buf = kmalloc(peer_len, gfp);
	rctx->ss_buf = kzalloc(clen, gfp);
	rctx->ref_buf = kzalloc_obj(u64, gfp);
	if (!rctx->peer_buf || !rctx->ss_buf || !rctx->ref_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	nents = sg_nents_for_len(req->src, peer_len);
	if (nents < 0 ||
	    sg_pcopy_to_buffer(req->src, nents, rctx->peer_buf,
			       peer_len, 0) != peer_len) {
		ret = -EINVAL;
		goto out_free;
	}

	rctx->peer_dma = cmh_dma_map_single(rctx->peer_buf, peer_len,
					    DMA_TO_DEVICE);
	rctx->ss_dma = cmh_dma_map_single(rctx->ss_buf, clen,
					  DMA_FROM_DEVICE);
	rctx->ref_dma = cmh_dma_map_single(rctx->ref_buf, sizeof(u64),
					   DMA_FROM_DEVICE);

	if (cmh_dma_map_error(rctx->peer_dma) ||
	    cmh_dma_map_error(rctx->ss_dma) ||
	    cmh_dma_map_error(rctx->ref_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	swap = PKE_SWAP_FLAGS;
	dma_swap = pke_swap_flags(ctx->curve);
	rctx->dma_swap = dma_swap;

	dd = cmh_core_select_instance(CMH_CORE_PKE);
	rctx->mbx_idx = dd.mbx_idx;

	rctx->sk_buf = kmemdup(ctx->key.raw.data, ctx->key.raw.len, gfp);
	if (!rctx->sk_buf) {
		ret = -ENOMEM;
		goto out_unmap;
	}
	rctx->sk_dma = cmh_dma_map_single(rctx->sk_buf, ctx->key.raw.len,
					  DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->sk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], 5);
	idx = 1;
	vcq_add_sys_write(&vcq[idx], SYS_REF_TEMP, rctx->sk_dma,
			  SYS_REF_NONE, ctx->key.raw.len,
			  ctx->key.raw.sys_type);
	vcq[idx].id |= dma_swap;
	idx++;
	vcq_add_sys_new(&vcq[idx++], 0, rctx->ref_dma, clen);
	vcq_add_pke_ecdh(&vcq[idx++], dd.core_id, ctx->curve, clen,
			 clen, ss_type, rctx->peer_dma,
			 SYS_REF_TEMP, SYS_REF_LAST, swap);
	vcq_add_pke_flush(&vcq[idx++], dd.core_id);

	ret = cmh_tm_submit_async(vcq, 5, 1, dd.mbx_idx,
				  cmh_ecdh_ss_phase1_complete, req,
				  !!(req->base.flags &
				     CRYPTO_TFM_REQ_MAY_BACKLOG), 0);
	if (ret == -EBUSY)
		return -EBUSY;
	if (!ret)
		return -EINPROGRESS;

out_unmap:
	if (!cmh_dma_map_error(rctx->sk_dma))
		cmh_dma_unmap_single(rctx->sk_dma, rctx->sk_len,
				     DMA_TO_DEVICE);
	if (!cmh_dma_map_error(rctx->ss_dma))
		cmh_dma_unmap_single(rctx->ss_dma, clen,
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->ref_dma))
		cmh_dma_unmap_single(rctx->ref_dma, sizeof(u64),
				     DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(rctx->peer_dma))
		cmh_dma_unmap_single(rctx->peer_dma, peer_len,
				     DMA_TO_DEVICE);

out_free:
	kfree_sensitive(rctx->sk_buf);
	kfree(rctx->ref_buf);
	kfree_sensitive(rctx->ss_buf);
	kfree(rctx->peer_buf);
	return ret;
}

static unsigned int cmh_ecdh_max_size(struct crypto_kpp *tfm)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);

	/* Max output = X||Y for generate_public_key (NIST) */
	return 2 * ctx->clen;
}

static unsigned int cmh_x25519_max_size(struct crypto_kpp *tfm)
{
	return pke_curve_clen(PKE_CURVE_25519); /* single coordinate */
}

static int cmh_ecdh_p256_init(struct crypto_kpp *tfm)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_P256;
	ctx->clen = pke_curve_clen(PKE_CURVE_P256);
	tfm->reqsize = sizeof(struct cmh_ecdh_reqctx);
	return 0;
}

static int cmh_ecdh_p384_init(struct crypto_kpp *tfm)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_P384;
	ctx->clen = pke_curve_clen(PKE_CURVE_P384);
	tfm->reqsize = sizeof(struct cmh_ecdh_reqctx);
	return 0;
}

static int cmh_x25519_init(struct crypto_kpp *tfm)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_25519;
	ctx->clen = pke_curve_clen(PKE_CURVE_25519);
	tfm->reqsize = sizeof(struct cmh_ecdh_reqctx);
	return 0;
}

static void cmh_ecdh_exit(struct crypto_kpp *tfm)
{
	struct cmh_ecdh_tfm_ctx *ctx = cmh_ecdh_ctx(tfm);

	cmh_key_destroy(&ctx->key);
}

static struct kpp_alg cmh_ecdh_algs[] = {
	{
		.set_secret		= cmh_ecdh_set_secret_nist,
		.generate_public_key	= cmh_ecdh_generate_public_key,
		.compute_shared_secret	= cmh_ecdh_compute_shared_secret,
		.max_size		= cmh_ecdh_max_size,
		.init			= cmh_ecdh_p256_init,
		.exit			= cmh_ecdh_exit,
		.base = {
			.cra_name	  = "ecdh-nist-p256",
			.cra_driver_name  = "cri-cmh-ecdh-nist-p256",
			.cra_priority	  = 300,
			.cra_flags	  = CRYPTO_ALG_ASYNC,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdh_tfm_ctx),
		},
	},
	{
		.set_secret		= cmh_ecdh_set_secret_nist,
		.generate_public_key	= cmh_ecdh_generate_public_key,
		.compute_shared_secret	= cmh_ecdh_compute_shared_secret,
		.max_size		= cmh_ecdh_max_size,
		.init			= cmh_ecdh_p384_init,
		.exit			= cmh_ecdh_exit,
		.base = {
			.cra_name	  = "ecdh-nist-p384",
			.cra_driver_name  = "cri-cmh-ecdh-nist-p384",
			.cra_priority	  = 300,
			.cra_flags	  = CRYPTO_ALG_ASYNC,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdh_tfm_ctx),
		},
	},
	{
		.set_secret		= cmh_ecdh_set_secret_x25519,
		.generate_public_key	= cmh_ecdh_generate_public_key,
		.compute_shared_secret	= cmh_ecdh_compute_shared_secret,
		.max_size		= cmh_x25519_max_size,
		.init			= cmh_x25519_init,
		.exit			= cmh_ecdh_exit,
		.base = {
			.cra_name	  = "curve25519",
			.cra_driver_name  = "cri-cmh-curve25519",
			.cra_priority	  = 300,
			.cra_flags	  = CRYPTO_ALG_ASYNC,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdh_tfm_ctx),
		},
	},
};

/**
 * cmh_pke_ecdh_register() - Register ECDH kpp algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_pke_ecdh_register(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(cmh_ecdh_algs); i++) {
		ret = crypto_register_kpp(&cmh_ecdh_algs[i]);
		if (ret) {
			dev_err(cmh_dev(), "cmh: failed to register %s (%d)\n",
				cmh_ecdh_algs[i].base.cra_name, ret);
			goto err_unregister;
		}
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_kpp(&cmh_ecdh_algs[i]);
	return ret;
}

/**
 * cmh_pke_ecdh_unregister() - Unregister ECDH kpp algorithms from the crypto framework
 */
void cmh_pke_ecdh_unregister(void)
{
	int i = ARRAY_SIZE(cmh_ecdh_algs);

	while (i--)
		crypto_unregister_kpp(&cmh_ecdh_algs[i]);
}
