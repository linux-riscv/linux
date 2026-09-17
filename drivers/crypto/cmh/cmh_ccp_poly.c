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
 * full VCQ asynchronously in .final().  Because the CCP core exposes no
 * external save/restore, input is buffered in kernel memory and capped
 * at POLY_MAX_DATA (64 KB).  Past that cap -- or when the flat export
 * window is exceeded -- the request transparently switches to the
 * Poly1305 library (<crypto/poly1305.h>), which keeps arbitrary-length
 * MACs and transform clone (export/import) conformant with O(1) memory.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <crypto/poly1305.h>
#include <linux/scatterlist.h>
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
 * Per-transform cap on total bytes buffered across all_chunks.  Bounds
 * the memory an AF_ALG client can pin by repeatedly opening request
 * sockets, updating, and abandoning them (the crypto API has no
 * per-request destructor, so their chunks live until the TFM is freed).
 */
#define CMH_POLY_TFM_MAX_BUFFERED	(16 * 1024 * 1024)

/*
 * Per-transform context -- stores the raw 32-byte key (r || s).
 *
 * Only the raw-key path is supported for standalone Poly1305.
 */
struct cmh_poly_tfm_ctx {
	u8  *key;                       /* kmalloc'd (r || s); DMA-safe */
	dma_addr_t rkey_dma;
	dma_addr_t skey_dma;
	u32 keylen;
	bool has_key;
	spinlock_t         chunk_lock;  /* protects all_chunks + tfm_buffered */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
	size_t             tfm_buffered; /* bytes on all_chunks; DoS cap */
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
	bool switched;			/* handed off to the Poly1305 library */
	struct poly1305_desc_ctx fb_state;	/* SW fallback running state */
	u8  *buf;		/* linearised in final() */
	/* DMA state for async final */
	dma_addr_t in_dma;
	dma_addr_t tag_dma;
	u8 *tag_buf;
	struct vcq_cmd packed[CMH_POLY_MAX_PACKED];
};

/*
 * Export/import (transform clone): the CCP core lacks external
 * save/restore, so the driver serialises its accumulated input for the
 * common (bounded) case (CMH_POLY_FMT_RAW).  When the input exceeds the
 * HW cap (POLY_MAX_DATA, 64 KB) or the flat export window, the request
 * switches to the Poly1305 library and serialises the library's
 * fixed-size running state (CMH_POLY_FMT_FB), so arbitrary-length MACs
 * and transform clone both stay conformant with O(1) driver memory.
 */
#define CMH_POLY_FMT_RAW 0
#define CMH_POLY_FMT_FB  1

struct cmh_poly_export_state {
	u8  format;
	u8  __pad[3];
	u32 total_len;
	u8  data[];
};

#define CMH_POLY_STATE_SIZE 4096
#define CMH_POLY_EXPORT_MAX \
	(CMH_POLY_STATE_SIZE - sizeof(struct cmh_poly_export_state))

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

	/*
	 * DMA the key from its own kmalloc'd buffer, not an inline tfm-ctx
	 * field: a standalone allocation is DMA-safe and cannot share a
	 * cacheline with CPU-written ctx fields (chunk_lock, all_chunks).
	 */
	if (!tctx->key) {
		tctx->key = kmalloc(POLY1305_KEY_SIZE, GFP_KERNEL);
		if (!tctx->key)
			return -ENOMEM;
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
		tctx->tfm_buffered -= c->len;
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);
	rctx->total_len = 0;
}

/* Software-fallback helpers (arbitrary-length + transform-clone support) */

/* Feed a scatterlist to the Poly1305 library, segment by segment. */
static void cmh_poly_fb_feed_sg(struct poly1305_desc_ctx *desc,
				struct scatterlist *sg, u32 len)
{
	struct sg_mapping_iter miter;
	u32 remaining = len;

	sg_miter_start(&miter, sg, sg_nents(sg),
		       SG_MITER_FROM_SG | SG_MITER_ATOMIC);
	while (remaining && sg_miter_next(&miter)) {
		u32 n = min_t(u32, miter.length, remaining);

		poly1305_update(desc, miter.addr, n);
		remaining -= n;
	}
	sg_miter_stop(&miter);
}

/*
 * Switch a request from the HW-buffered path to the Poly1305 library:
 * initialise the library state with the transform key, replay every
 * accumulated chunk through it, then drop the chunks.  Afterwards the
 * request is O(1) in memory and no longer input-capped.
 */
static int cmh_poly_switch_to_fb(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_poly_chunk *c;

	if (!tctx->has_key)
		return -ENOKEY;

	poly1305_init(&rctx->fb_state, tctx->key);
	list_for_each_entry(c, &rctx->chunks, list)
		poly1305_update(&rctx->fb_state, c->data, c->len);
	cmh_poly_free_chunks(rctx, tctx);
	rctx->switched = true;
	return 0;
}

/* Forward the current update() payload to the library. */
static void cmh_poly_fb_forward(struct ahash_request *req,
				struct cmh_poly_reqctx *rctx)
{
	if (req->base.flags & CRYPTO_AHASH_REQ_VIRT)
		poly1305_update(&rctx->fb_state, req->svirt, req->nbytes);
	else
		cmh_poly_fb_feed_sg(&rctx->fb_state, req->src, req->nbytes);
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

	/* Already handed off to the library: forward directly (O(1) mem). */
	if (rctx->switched) {
		cmh_poly_fb_forward(req, rctx);
		return 0;
	}

	/*
	 * Exceeding the HW input cap: switch to the Poly1305 library
	 * (replaying the buffered chunks) rather than failing, then
	 * forward this update.
	 */
	if (req->nbytes > POLY_MAX_DATA - rctx->total_len) {
		ret = cmh_poly_switch_to_fb(req);
		if (ret)
			goto err_free_chunks;
		cmh_poly_fb_forward(req, rctx);
		return 0;
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
	spin_lock_bh(&tctx->chunk_lock);
	if (tctx->tfm_buffered + chunk->len > CMH_POLY_TFM_MAX_BUFFERED) {
		spin_unlock_bh(&tctx->chunk_lock);
		kfree_sensitive(chunk);
		ret = -ENOMEM;
		goto err_free_chunks;
	}
	list_add_tail(&chunk->list, &rctx->chunks);
	list_add_tail(&chunk->tfm_node, &tctx->all_chunks);
	tctx->tfm_buffered += chunk->len;
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

	/* Switched to the Poly1305 library: complete there (synchronous). */
	if (rctx->switched) {
		poly1305_final(&rctx->fb_state, req->result);
		return 0;
	}

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
	if (ret) {
		/*
		 * Synchronous rejection (e.g. -EAGAIN: CMQ full, no backlog).
		 * Free only the per-submit transients and keep the accumulated
		 * chunks intact so the caller can retry the identical final().
		 * If no retry comes, exit_tfm reclaims the orphaned chunks; the
		 * per-tfm buffered-byte cap bounds how much stays pinned.
		 */
		if (rctx->total_len > 0)
			cmh_dma_unmap_single(rctx->in_dma, rctx->total_len,
					     DMA_TO_DEVICE);
		cmh_dma_unmap_single(rctx->tag_dma, POLY1305_DIGEST_SIZE,
				     DMA_FROM_DEVICE);
		kfree(rctx->tag_buf);
		rctx->tag_buf = NULL;
		kfree_sensitive(rctx->buf);
		rctx->buf = NULL;
		/* Keep chunks + total_len so the retry rebuilds the buffer. */
		return ret;
	}

	return -EINPROGRESS;

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
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_poly_export_state *state = out;
	struct cmh_poly_chunk *chunk;
	u32 offset = 0;
	int ret;

	BUILD_BUG_ON(sizeof(struct poly1305_desc_ctx) > CMH_POLY_EXPORT_MAX);

	/*
	 * If more data is buffered than the flat window holds, switch to
	 * the Poly1305 library so a bounded, fixed-size state can be
	 * exported -- making export/import (clone) work at any length.
	 */
	if (!rctx->switched && rctx->total_len > CMH_POLY_EXPORT_MAX) {
		ret = cmh_poly_switch_to_fb(req);
		if (ret)
			return ret;
	}

	/* Zero the whole state buffer so no kernel memory leaks out. */
	memset(state, 0, crypto_ahash_statesize(tfm));

	if (rctx->switched) {
		state->format = CMH_POLY_FMT_FB;
		memcpy(state->data, &rctx->fb_state, sizeof(rctx->fb_state));
		return 0;
	}

	state->format = CMH_POLY_FMT_RAW;
	state->total_len = rctx->total_len;
	list_for_each_entry(chunk, &rctx->chunks, list) {
		memcpy(state->data + offset, chunk->data, chunk->len);
		offset += chunk->len;
	}
	return 0;
}

static int cmh_poly_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_poly_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_poly_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_poly_export_state *state = in;
	struct cmh_poly_chunk *chunk;

	memset(rctx, 0, sizeof(*rctx));
	INIT_LIST_HEAD(&rctx->chunks);

	/* Fallback-format state: restore the Poly1305 library state. */
	if (state->format == CMH_POLY_FMT_FB) {
		memcpy(&rctx->fb_state, state->data, sizeof(rctx->fb_state));
		rctx->switched = true;
		return 0;
	}

	if (state->format != CMH_POLY_FMT_RAW)
		return -EINVAL;

	if (state->total_len > CMH_POLY_EXPORT_MAX)
		return -EINVAL;

	if (state->total_len) {
		chunk = kmalloc(sizeof(*chunk) + state->total_len,
				req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
				GFP_KERNEL : GFP_ATOMIC);
		if (!chunk)
			return -ENOMEM;
		chunk->len = state->total_len;
		memcpy(chunk->data, state->data, state->total_len);
		list_add_tail(&chunk->list, &rctx->chunks);
		spin_lock_bh(&tctx->chunk_lock);
		list_add_tail(&chunk->tfm_node, &tctx->all_chunks);
		spin_unlock_bh(&tctx->chunk_lock);
		rctx->total_len = state->total_len;
	}
	return 0;
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
		tctx->tfm_buffered -= c->len;
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);

	if (tctx->has_key) {
		cmh_dma_unmap_single(tctx->rkey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
		cmh_dma_unmap_single(tctx->skey_dma, CCP_POLY_KEY_SIZE,
				     DMA_TO_DEVICE);
	}
	kfree_sensitive(tctx->key);
	tctx->key = NULL;
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
		.statesize	= CMH_POLY_STATE_SIZE,
		.base		= {
			.cra_name	 = "poly1305",
			.cra_driver_name = "rambus-cmh-poly1305",
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

	if (!cmh_core_present(CMH_CORE_CCP))
		return 0;

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
	if (!cmh_core_present(CMH_CORE_CCP))
		return;

	crypto_unregister_ahash(&cmh_poly1305_alg);
	dev_dbg(cmh_dev(), "cmh_ccp_poly: unregistered poly1305\n");
}
