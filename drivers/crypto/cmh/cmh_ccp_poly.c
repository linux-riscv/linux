// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API Poly1305 (ahash) Driver
 *
 * Registers "poly1305" as an ahash algorithm with the Linux crypto
 * subsystem, backed by the CMH CCP core.
 *
 * Poly1305 is a one-time authenticator that produces a 16-byte MAC.
 * It requires two 16-byte keys: r (clamped multiplier) and s (nonce).
 *
 * Key format: 32 bytes = r_key[0..15] || s_key[16..31]
 * This matches the Poly1305 key layout in RFC 7539 S2.5.
 *
 * VCQ sequence:
 *   SYS_CMD_WRITE(s_key) + SYS_CMD_WRITE(r_key)
 *   + CCP_CMD_POLY1305_INIT + CCP_CMD_FINAL + CCP_CMD_FLUSH
 *
 * Both keys are written to SYS_REF_TEMP; the CMH eSW stacks them
 * so that POLY1305_INIT finds r_key (most recent) as rkey and
 * s_key (previous) as skey.
 *
 * The ahash interface accumulates data via .update() and submits the
 * full VCQ asynchronously in .final().
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_ccp.h"
#include "cmh_vcq.h"
#include "cmh_ccp_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

#define POLY1305_DIGEST_SIZE	16U
#define POLY1305_BLOCK_SIZE	16U
#define POLY1305_KEY_SIZE	32U	/* r(16) + s(16) */

/*
 * Maximum accumulated data for Poly1305 -- driver-imposed, not HW.
 *
 * The CCP core does not expose external save/restore VCQ commands,
 * so the driver must accumulate all data in kernel memory via
 * .update() and submit it atomically in .final().  This cap limits
 * the per-request kernel allocation.
 */
#define POLY_MAX_DATA		(64 * 1024)

/*
 * Per-transform context -- stores the raw 32-byte key (r || s).
 *
 * Only the raw-key path is supported for standalone Poly1305.
 */
struct cmh_poly_tfm_ctx {
	u8  key[POLY1305_KEY_SIZE];
	dma_addr_t rkey_dma;
	dma_addr_t skey_dma;
	u32 keylen;
	bool has_key;
	spinlock_t         chunk_lock;  /* protects all_chunks */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
};

/* Chunk node for O(1) update() appends */
struct cmh_poly_chunk {
	struct list_head list;
	struct list_head tfm_node; /* per-tfm orphan tracking */
	u32 len;
	u8  data[];
};

/* Per-request context (lives in ahash_request::__ctx) */

/*
 * Maximum payload commands:
 *   SYS_CMD_WRITE(s) + SYS_CMD_WRITE(r) + POLY1305_INIT
 *   + CCP_CMD_FINAL + FLUSH = 5
 */
#define CMH_POLY_MAX_PAYLOAD	5
#define CMH_POLY_MAX_PACKED	(CMH_POLY_MAX_PAYLOAD * 2)

struct cmh_poly_reqctx {
	struct list_head chunks;
	u32  total_len;
	u8  *buf;		/* linearised in final() */
	/* DMA state for async final */
	dma_addr_t in_dma;
	dma_addr_t tag_dma;
	u8 *tag_buf;
	struct vcq_cmd packed[CMH_POLY_MAX_PACKED];
};

/*
 * Export/import: not supported.
 *
 * The CCP core lacks external save/restore VCQ commands, so there is
 * no way to checkpoint intermediate Poly1305 state to host memory.
 * Pending eSW ABI extension to add save/restore for the CCP core.
 */

static void vcq_add_ccp_poly_init(struct vcq_cmd *slot, u32 core_id,
				  u64 rkey_ref, u32 rkeylen,
				  u64 skey_ref, u32 skeylen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_POLY1305_INIT);
	slot->hwc.ccp.cmd_poly.rkey = rkey_ref;
	slot->hwc.ccp.cmd_poly.rkeylen = rkeylen;
	slot->hwc.ccp.cmd_poly.skey = skey_ref;
	slot->hwc.ccp.cmd_poly.skeylen = skeylen;
}

static void vcq_add_ccp_poly_final(struct vcq_cmd *slot, u32 core_id,
				   u64 input_dma, u64 tag_dma,
				   u32 iolen, u32 taglen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_FINAL);
	slot->hwc.ccp.cmd_final.input = input_dma;
	slot->hwc.ccp.cmd_final.output = 0;
	slot->hwc.ccp.cmd_final.tag = tag_dma;
	slot->hwc.ccp.cmd_final.iolen = iolen;
	slot->hwc.ccp.cmd_final.taglen = taglen;
}

static int cmh_poly_setkey(struct crypto_ahash *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);

	/* Poly1305: exactly 32 bytes (r[16] + s[16]) */
	if (keylen != POLY1305_KEY_SIZE)
		return -EINVAL;

	/* Unmap old key DMA if re-keying */
	if (tctx->has_key) {
		cmh_dma_unmap_single(tctx->rkey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
		cmh_dma_unmap_single(tctx->skey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
	}

	memcpy(tctx->key, key, POLY1305_KEY_SIZE);
	tctx->keylen = POLY1305_KEY_SIZE;

	/*
	 * Pre-map both key halves for DMA.  The key buffer lives in
	 * the tfm context and is stable until exit_tfm() or re-setkey.
	 */
	tctx->skey_dma = cmh_dma_map_single(tctx->key + CCP_POLY_KEY_SIZE,
					    CCP_POLY_KEY_SIZE,
					     DMA_TO_DEVICE);
	if (cmh_dma_map_error(tctx->skey_dma)) {
		tctx->has_key = false;
		return -ENOMEM;
	}

	tctx->rkey_dma = cmh_dma_map_single(tctx->key, CCP_POLY_KEY_SIZE,
					    DMA_TO_DEVICE);
	if (cmh_dma_map_error(tctx->rkey_dma)) {
		cmh_dma_unmap_single(tctx->skey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
		tctx->has_key = false;
		return -ENOMEM;
	}

	tctx->has_key = true;
	return 0;
}

static void cmh_poly_free_chunks(struct cmh_poly_reqctx *rctx,
				 struct cmh_poly_tfm_ctx *tctx)
{
	struct cmh_poly_chunk *c, *tmp;

	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(c, tmp, &rctx->chunks, list) {
		list_del(&c->list);
		list_del(&c->tfm_node);
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);
}

static int cmh_poly_init(struct ahash_request *req)
{
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(*rctx));
	INIT_LIST_HEAD(&rctx->chunks);
	return 0;
}

static int cmh_poly_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_poly_chunk *chunk;
	gfp_t gfp;
	int ret;

	if (!req->nbytes)
		return 0;

	if (req->nbytes > POLY_MAX_DATA - rctx->total_len) {
		ret = -EINVAL;
		goto err_free_chunks;
	}

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;
	chunk = kmalloc(sizeof(*chunk) + req->nbytes, gfp);
	if (!chunk) {
		ret = -ENOMEM;
		goto err_free_chunks;
	}

	chunk->len = req->nbytes;
	if (req->base.flags & CRYPTO_AHASH_REQ_VIRT)
		memcpy(chunk->data, req->svirt, req->nbytes);
	else
		scatterwalk_map_and_copy(chunk->data, req->src,
					 0, req->nbytes, 0);
	list_add_tail(&chunk->list, &rctx->chunks);
	spin_lock_bh(&tctx->chunk_lock);
	list_add_tail(&chunk->tfm_node, &tctx->all_chunks);
	spin_unlock_bh(&tctx->chunk_lock);
	rctx->total_len += req->nbytes;
	return 0;

err_free_chunks:
	/*
	 * Terminal error -- free all previously accumulated chunks.
	 * Callers may not call .final() on error, so they would leak.
	 */
	cmh_poly_free_chunks(rctx, tctx);
	return ret;
}

static void cmh_poly_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->total_len > 0)
		cmh_dma_unmap_single(rctx->in_dma, rctx->total_len,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->tag_dma, POLY1305_DIGEST_SIZE,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->tag_buf, POLY1305_DIGEST_SIZE);

	kfree(rctx->tag_buf);
	rctx->tag_buf = NULL;
	cmh_poly_free_chunks(rctx, tctx);
	kfree_sensitive(rctx->buf);
	rctx->buf = NULL;
	rctx->total_len = 0;
	cmh_complete(&req->base, error);
}

static int cmh_poly_final(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);
	struct vcq_cmd cmds[CMH_POLY_MAX_PAYLOAD];
	struct core_dispatch d;
	s32 target_mbx;
	u32 core_id;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (!tctx->has_key) {
		ret = -ENOKEY;
		goto out_free_chunks;
	}

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/* Linearise chunks into a single contiguous buffer for DMA */
	if (rctx->total_len > 0) {
		struct cmh_poly_chunk *c;
		u32 off = 0;

		rctx->buf = kmalloc(rctx->total_len, gfp);
		if (!rctx->buf) {
			ret = -ENOMEM;
			goto out_free_chunks;
		}
		list_for_each_entry(c, &rctx->chunks, list) {
			memcpy(rctx->buf + off, c->data, c->len);
			off += c->len;
		}
	}

	/* Tag output buffer */
	rctx->tag_buf = kzalloc(POLY1305_DIGEST_SIZE, gfp);
	if (!rctx->tag_buf) {
		ret = -ENOMEM;
		goto out_free_buf;
	}

	rctx->tag_dma = cmh_dma_map_single(rctx->tag_buf,
					   POLY1305_DIGEST_SIZE,
					    DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->tag_dma)) {
		ret = -ENOMEM;
		goto out_free_tag;
	}

	/* Map input data */
	if (rctx->total_len > 0) {
		rctx->in_dma = cmh_dma_map_single(rctx->buf, rctx->total_len,
						  DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->in_dma)) {
			ret = -ENOMEM;
			goto out_unmap_tag;
		}
	}

	/*
	 * Key DMA handles are pre-mapped in setkey() and live in
	 * the tfm context.  Use them directly for the VCQ writes.
	 */

	d = cmh_core_select_instance(CMH_CORE_CCP);
	target_mbx = d.mbx_idx;
	core_id = d.core_id;
	idx = 0;

	/* Write s_key to SYS_REF_TEMP first (bottom of stack) */
	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP,
			  (u64)tctx->skey_dma, SYS_REF_NONE,
			  CCP_POLY_KEY_SIZE,
			  SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_CCP));

	/* Write r_key to SYS_REF_TEMP second (top of stack) */
	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP,
			  (u64)tctx->rkey_dma, SYS_REF_NONE,
			  CCP_POLY_KEY_SIZE,
			  SYS_TYPE_SET(SYS_TYPE_FLAG_PT, CORE_ID_CCP));

	/* POLY1305_INIT: rkey=TEMP (top), skey=TEMP (next) */
	vcq_add_ccp_poly_init(&cmds[idx++], core_id, SYS_REF_TEMP,
			      CCP_POLY_KEY_SIZE, SYS_REF_TEMP,
			      CCP_POLY_KEY_SIZE);

	/* FINAL: data -> tag */
	vcq_add_ccp_poly_final(&cmds[idx++], core_id,
			       rctx->total_len > 0 ? (u64)rctx->in_dma : 0,
			       (u64)rctx->tag_dma, rctx->total_len,
			       POLY1305_DIGEST_SIZE);

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_POLY_MAX_PACKED, target_mbx,
					    cmh_poly_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_unmap_in;

	return -EINPROGRESS;

out_unmap_in:
	if (rctx->total_len > 0 && rctx->in_dma)
		cmh_dma_unmap_single(rctx->in_dma, rctx->total_len,
				     DMA_TO_DEVICE);
out_unmap_tag:
	cmh_dma_unmap_single(rctx->tag_dma, POLY1305_DIGEST_SIZE,
			     DMA_FROM_DEVICE);
out_free_tag:
	kfree(rctx->tag_buf);
out_free_buf:
	kfree_sensitive(rctx->buf);
	rctx->buf = NULL;
out_free_chunks:
	cmh_poly_free_chunks(rctx, tctx);
	rctx->total_len = 0;
	return ret;
}

static int cmh_poly_export(struct ahash_request *req, void *out)
{
	return -EOPNOTSUPP;
}

static int cmh_poly_import(struct ahash_request *req, const void *in)
{
	return -EOPNOTSUPP;
}

static int cmh_poly_finup(struct ahash_request *req)
{
	int err;

	err = cmh_poly_update(req);
	if (err)
		return err;
	return cmh_poly_final(req);
}

static int cmh_poly_digest(struct ahash_request *req)
{
	int err;

	err = cmh_poly_init(req);
	if (err)
		return err;
	return cmh_poly_finup(req);
}

static int cmh_poly_init_tfm(struct crypto_ahash *tfm)
{
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);

	memset(tctx, 0, sizeof(*tctx));
	spin_lock_init(&tctx->chunk_lock);
	INIT_LIST_HEAD(&tctx->all_chunks);
	crypto_ahash_set_reqsize(tfm, sizeof(struct cmh_poly_reqctx));
	return 0;
}

static void cmh_poly_exit_tfm(struct crypto_ahash *tfm)
{
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_poly_chunk *c, *tmp;

	/* Free any orphaned chunks (e.g. testmgr export/reimport poison) */
	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(c, tmp, &tctx->all_chunks, tfm_node) {
		list_del(&c->tfm_node);
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);

	if (tctx->has_key) {
		cmh_dma_unmap_single(tctx->rkey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
		cmh_dma_unmap_single(tctx->skey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
	}
	memzero_explicit(tctx->key, POLY1305_KEY_SIZE);
}

static struct ahash_alg cmh_poly1305_alg = {
	.init		= cmh_poly_init,
	.update		= cmh_poly_update,
	.final		= cmh_poly_final,
	.finup		= cmh_poly_finup,
	.digest		= cmh_poly_digest,
	.export		= cmh_poly_export,
	.import		= cmh_poly_import,
	.setkey		= cmh_poly_setkey,
	.init_tfm	= cmh_poly_init_tfm,
	.exit_tfm	= cmh_poly_exit_tfm,
	.halg		= {
		.digestsize	= POLY1305_DIGEST_SIZE,
		.statesize	= sizeof(struct cmh_poly_reqctx),
		.base		= {
			.cra_name	 = "poly1305",
			.cra_driver_name = "cri-cmh-poly1305",
			.cra_priority	 = 300,
			.cra_flags	 = CRYPTO_ALG_KERN_DRIVER_ONLY |
					   CRYPTO_ALG_NO_FALLBACK |
					   CRYPTO_ALG_ASYNC |
					   CRYPTO_ALG_REQ_VIRT,
			.cra_blocksize	 = POLY1305_BLOCK_SIZE,
			.cra_ctxsize	 = sizeof(struct cmh_poly_tfm_ctx),
			.cra_module	 = THIS_MODULE,
		},
	},
};

/**
 * cmh_ccp_poly_register() - Register Poly1305 hash algorithm with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_ccp_poly_register(void)
{
	int ret;

	ret = crypto_register_ahash(&cmh_poly1305_alg);
	if (ret)
		dev_err(cmh_dev(), "cmh_ccp_poly: failed to register poly1305 (rc=%d)\n",
			ret);
	else
		dev_dbg(cmh_dev(), "cmh_ccp_poly: registered poly1305\n");

	return ret;
}

/**
 * cmh_ccp_poly_unregister() - Unregister Poly1305 hash algorithm from the crypto framework
 */
void cmh_ccp_poly_unregister(void)
{
	crypto_unregister_ahash(&cmh_poly1305_alg);
	dev_dbg(cmh_dev(), "cmh_ccp_poly: unregistered poly1305\n");
}
