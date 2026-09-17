// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM3 Hash Driver (CORE_ID_SM3)
 *
 * Registers an asynchronous hash (ahash) algorithm for SM3
 * (GB/T 32905-2016) using the CMH SM3 core.  This is a standalone
 * driver separate from cmh_hash.c (which handles HC-based SHA-2/3/SHAKE)
 * because SM3 runs on a different hardware core with its own command
 * IDs and context layout.
 *
 * Incremental HW update model (same pattern as cmh_hash.c).  The driver
 * sets CRYPTO_AHASH_ALG_BLOCK_ONLY, so the Crypto API buffers partial
 * blocks and .update() only ever sees whole-block-aligned data:
 *
 *   .init()   -> software-only: zero per-request context
 *   .update() -> SM3_CMD_INIT [+ RESTORE] + UPDATE + SAVE + FLUSH;
 *                return -EINPROGRESS, completing with the leftover byte
 *                count the API must buffer (0 when block-aligned)
 *   .finup()  -> SM3_CMD_INIT [+ RESTORE] [+ UPDATE] + FINAL + FLUSH
 *                (also serves .final via the API: nbytes == 0)
 *   .digest() -> INIT + UPDATE + FINAL + FLUSH (single-shot via finup)
 *   .export()/.import() -> software-only: copy the SM3 context
 *                checkpoint; the API appends its own partial-block buffer
 *
 * This is an sg-only driver (no CRYPTO_ALG_REQ_VIRT): BLOCK_ONLY buffer
 * prepending assumes scatterlists.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_sm3.h"
#include "cmh_vcq.h"
#include "cmh_txn.h"
#include "cmh_dma.h"

/* Per-Request State */

/*
 * Exported SM3 state -- serialised by .export(), deserialised by
 * .import().  This is what statesize advertises; the Crypto API
 * appends its own partial-block buffer on top.
 */
struct cmh_sm3_export_state {
	u8  checkpoint[SM3_CONTEXT_SIZE]; /* SM3 context from last SAVE */
	u32 hw_started;                   /* non-zero if checkpoint valid */
};

#define CMH_SM3_MAX_PAYLOAD    5   /* INIT + RESTORE + UPDATE + FINAL/SAVE + FLUSH */
#define CMH_SM3_MAX_PACKED     (CMH_SM3_MAX_PAYLOAD * 2)

/*
 * Checkpoint embedded inline: the kernel ahash API has no per-request
 * destructor, so a heap-allocated checkpoint leaks if a request is
 * abandoned without .final().
 *
 * Mapping the inline checkpoint for DMA is safe even on non-coherent
 * platforms: it is only ever mapped DMA_TO_DEVICE and its bytes are
 * frozen from dma_map_single() until the matching unmap (it is written
 * solely in the completion, after the unmap).  CPU writes to adjacent
 * fields sharing a cacheline never alter the checkpoint bytes, and a
 * TO_DEVICE unmap performs no cache invalidate; the shared-cacheline
 * hazard applies only to FROM_DEVICE buffers, which are kmalloc'd.
 */
struct cmh_sm3_reqctx {
	int    error;
	u32    hw_started;
	u32    has_checkpoint;
	u32    update_remainder; /* sub-block bytes the API must re-buffer */
	u8     checkpoint[SM3_CONTEXT_SIZE]; /* SM3 context from last SAVE */
	/* DMA state for current async operation */
	dma_addr_t ckpt_dma;
	dma_addr_t save_dma;
	dma_addr_t data_dma;
	dma_addr_t digest_dma;
	u8    *save_buf;
	u8    *data_buf;
	u32    data_len;
	u8    *digest_buf;
	struct vcq_cmd packed[CMH_SM3_MAX_PACKED];
};

/* VCQ Builders -- SM3 core (CORE_ID_SM3); generic flush from cmh_vcq.h */

static void vcq_add_sm3_init(struct vcq_cmd *slot, u32 core_id)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM3_CMD_INIT);
	/* SM3 has a single algorithm -- no algo selector field */
}

static void vcq_add_sm3_update(struct vcq_cmd *slot, u32 core_id, u64 input_phys, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM3_CMD_UPDATE);
	slot->hwc.sm3.cmd_update.input = input_phys;
	slot->hwc.sm3.cmd_update.inlen = len;
}

static void vcq_add_sm3_final(struct vcq_cmd *slot, u32 core_id, u64 digest_phys, u32 outlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM3_CMD_FINAL);
	slot->hwc.sm3.cmd_final.digest = digest_phys;
	slot->hwc.sm3.cmd_final.outlen = outlen;
}

static void vcq_add_sm3_save(struct vcq_cmd *slot, u32 core_id, u64 output_phys, u32 outlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM3_CMD_SAVE);
	slot->hwc.sm3.cmd_save.output = output_phys;
	slot->hwc.sm3.cmd_save.outlen = outlen;
}

static void vcq_add_sm3_restore(struct vcq_cmd *slot, u32 core_id, u64 input_phys, u32 inlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM3_CMD_RESTORE);
	slot->hwc.sm3.cmd_restore.input = input_phys;
	slot->hwc.sm3.cmd_restore.inlen = inlen;
}

/* Request Context Cleanup */

static void cmh_sm3_free_reqctx(struct cmh_sm3_reqctx *rctx)
{
	rctx->has_checkpoint = 0;
}

/* VCQ Packing + Submit */

/* ahash Operations */

static int cmh_sm3_init(struct ahash_request *req)
{
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(*rctx));
	return 0;
}

/*
 * Update completion -- takes ownership of save_buf as new checkpoint.
 */
static void cmh_sm3_update_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, SM3_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->save_dma, SM3_CONTEXT_SIZE,
			     DMA_FROM_DEVICE);
	cmh_dma_unmap_single(rctx->data_dma, rctx->data_len,
			     DMA_TO_DEVICE);

	if (!error) {
		memcpy(rctx->checkpoint, rctx->save_buf, SM3_CONTEXT_SIZE);
		rctx->has_checkpoint = 1;
		kfree(rctx->save_buf);
		rctx->save_buf = NULL;
		rctx->hw_started = 1;
		/* Hand the API the sub-block remainder it must re-buffer. */
		error = rctx->update_remainder;
	} else {
		kfree(rctx->save_buf);
		rctx->save_buf = NULL;
		rctx->error = error;
	}

	kfree(rctx->data_buf);
	rctx->data_buf = NULL;
	rctx->data_len = 0;

	cmh_complete(&req->base, error);
}

static int cmh_sm3_update(struct ahash_request *req)
{
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);
	struct vcq_cmd cmds[CMH_SM3_MAX_PAYLOAD];
	struct core_dispatch d;
	u32 full_len;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (rctx->error)
		return rctx->error;

	if (!req->nbytes)
		return 0;

	/* block size is a power of two, but modulo keeps the split exact. */
	rctx->update_remainder = req->nbytes % CMH_SM3_BLOCK_SIZE;
	full_len = req->nbytes - rctx->update_remainder;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/*
	 * Reject a single update whose linearisation would exceed the largest
	 * kmalloc: return a permanent -EMSGSIZE ("message too long") rather
	 * than a transient -ENOMEM the client would keep retrying.  __GFP_NOWARN
	 * keeps a borderline-large (but sub-cap) request quiet if it still
	 * cannot be satisfied.
	 */
	if (full_len > KMALLOC_MAX_SIZE)
		return -EMSGSIZE;

	rctx->data_buf = kmalloc(full_len, gfp | __GFP_NOWARN);
	if (!rctx->data_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(rctx->data_buf, req->src, 0, full_len, 0);

	rctx->data_len = full_len;

	rctx->save_buf = kzalloc(SM3_CONTEXT_SIZE, gfp);
	if (!rctx->save_buf) {
		ret = -ENOMEM;
		goto err_free;
	}

	rctx->data_dma = cmh_dma_map_single(rctx->data_buf, full_len,
					    DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->data_dma)) {
		ret = -ENOMEM;
		goto err_free;
	}

	rctx->save_dma = cmh_dma_map_single(rctx->save_buf, SM3_CONTEXT_SIZE,
					    DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->save_dma)) {
		ret = -ENOMEM;
		goto err_unmap_data;
	}

	rctx->ckpt_dma = DMA_MAPPING_ERROR;
	if (rctx->has_checkpoint) {
		rctx->ckpt_dma = cmh_dma_map_single(rctx->checkpoint,
						    SM3_CONTEXT_SIZE,
						     DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->ckpt_dma)) {
			ret = -ENOMEM;
			goto err_unmap_save;
		}
	}

	d = cmh_core_select_instance(CMH_CORE_SM3);
	idx = 0;

	vcq_add_sm3_init(&cmds[idx++], d.core_id);

	if (rctx->has_checkpoint)
		vcq_add_sm3_restore(&cmds[idx++], d.core_id,
				    (u64)rctx->ckpt_dma, SM3_CONTEXT_SIZE);

	vcq_add_sm3_update(&cmds[idx++], d.core_id,
			   (u64)rctx->data_dma, full_len);

	vcq_add_sm3_save(&cmds[idx++], d.core_id,
			 (u64)rctx->save_dma, SM3_CONTEXT_SIZE);

	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_SM3_MAX_PACKED,
					    d.mbx_idx,
					    cmh_sm3_update_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret && ret != -EBUSY)
		goto err_unmap_ckpt;

	if (ret == -EBUSY)
		return -EBUSY;
	return -EINPROGRESS;

err_unmap_ckpt:
	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, SM3_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
err_unmap_save:
	cmh_dma_unmap_single(rctx->save_dma, SM3_CONTEXT_SIZE,
			     DMA_FROM_DEVICE);
err_unmap_data:
	cmh_dma_unmap_single(rctx->data_dma, full_len, DMA_TO_DEVICE);
err_free:
	kfree(rctx->save_buf);
	rctx->save_buf = NULL;
	kfree(rctx->data_buf);
	rctx->data_buf = NULL;
	rctx->data_len = 0;
	return ret;
}

static void cmh_sm3_final_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, SM3_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
	if (rctx->data_buf)
		cmh_dma_unmap_single(rctx->data_dma, rctx->data_len,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->digest_dma, CMH_SM3_DIGEST_SIZE,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->digest_buf, CMH_SM3_DIGEST_SIZE);

	kfree(rctx->digest_buf);
	rctx->digest_buf = NULL;
	kfree(rctx->data_buf);
	rctx->data_buf = NULL;
	cmh_sm3_free_reqctx(rctx);
	cmh_complete(&req->base, error);
}

static int cmh_sm3_submit_final(struct ahash_request *req,
				u8 *data_buf, u32 data_len)
{
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);
	struct vcq_cmd cmds[CMH_SM3_MAX_PAYLOAD];
	struct core_dispatch d;
	u32 idx;
	int ret;
	gfp_t gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
		   GFP_KERNEL : GFP_ATOMIC;

	rctx->data_buf = data_buf;
	rctx->data_len = data_len;

	rctx->digest_buf = kzalloc(CMH_SM3_DIGEST_SIZE, gfp);
	if (!rctx->digest_buf) {
		ret = -ENOMEM;
		goto err_free_data;
	}

	rctx->digest_dma = cmh_dma_map_single(rctx->digest_buf,
					      CMH_SM3_DIGEST_SIZE,
					       DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->digest_dma)) {
		ret = -ENOMEM;
		goto err_free_digest;
	}

	rctx->data_dma = DMA_MAPPING_ERROR;
	if (data_buf && data_len > 0) {
		rctx->data_dma = cmh_dma_map_single(data_buf, data_len,
						    DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->data_dma)) {
			ret = -ENOMEM;
			goto err_unmap_digest;
		}
	}

	rctx->ckpt_dma = DMA_MAPPING_ERROR;
	if (rctx->has_checkpoint) {
		rctx->ckpt_dma = cmh_dma_map_single(rctx->checkpoint,
						    SM3_CONTEXT_SIZE,
						     DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->ckpt_dma)) {
			ret = -ENOMEM;
			goto err_unmap_data;
		}
	}

	d = cmh_core_select_instance(CMH_CORE_SM3);
	idx = 0;

	vcq_add_sm3_init(&cmds[idx++], d.core_id);

	if (rctx->has_checkpoint)
		vcq_add_sm3_restore(&cmds[idx++], d.core_id,
				    (u64)rctx->ckpt_dma, SM3_CONTEXT_SIZE);

	if (data_buf && data_len > 0)
		vcq_add_sm3_update(&cmds[idx++], d.core_id,
				   (u64)rctx->data_dma, data_len);

	vcq_add_sm3_final(&cmds[idx++], d.core_id,
			  (u64)rctx->digest_dma, CMH_SM3_DIGEST_SIZE);

	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_SM3_MAX_PACKED,
					    d.mbx_idx,
					    cmh_sm3_final_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto err_unmap_ckpt;

	return -EINPROGRESS;

err_unmap_ckpt:
	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, SM3_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
err_unmap_data:
	if (data_buf && data_len > 0)
		cmh_dma_unmap_single(rctx->data_dma, data_len,
				     DMA_TO_DEVICE);
err_unmap_digest:
	cmh_dma_unmap_single(rctx->digest_dma, CMH_SM3_DIGEST_SIZE,
			     DMA_FROM_DEVICE);
err_free_digest:
	kfree(rctx->digest_buf);
	rctx->digest_buf = NULL;
err_free_data:
	kfree(data_buf);
	rctx->data_buf = NULL;
	/*
	 * Preserve the SM3 checkpoint on failure: a synchronous rejection is
	 * retryable, and for a terminal error the inline checkpoint is freed
	 * with the request context, so it never leaks.  It is cleared only in
	 * the completion after a successful final().
	 */
	return ret;
}

static int cmh_sm3_finup(struct ahash_request *req);

/*
 * One-shot digest -- delegates to init + finup so that all data is
 * linearised and mapped through cmh_dma_map_single(), which is the
 * only DMA mapping path aware of all supported DMA backends.
 */
static int cmh_sm3_digest(struct ahash_request *req)
{
	int ret;

	ret = cmh_sm3_init(req);
	if (ret)
		return ret;
	return cmh_sm3_finup(req);
}

/*
 * .finup -- hash any remaining data and finalise in one transaction.
 * With BLOCK_ONLY the Crypto API prepends the bytes it held back, so
 * req->src already carries the full tail.  Also serves .final (nbytes
 * == 0).  Avoids ahash_def_finup(), which would clone via export/import.
 */
static int cmh_sm3_finup(struct ahash_request *req)
{
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);
	u32 data_len = req->nbytes;
	u8 *data_buf = NULL;
	gfp_t gfp;

	if (rctx->error)
		return rctx->error;

	if (data_len == 0)
		return cmh_sm3_submit_final(req, NULL, 0);

	/* Reject an oversized linearisation with a permanent -EMSGSIZE. */
	if (data_len > KMALLOC_MAX_SIZE)
		return -EMSGSIZE;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	data_buf = kmalloc(data_len, gfp | __GFP_NOWARN);
	if (!data_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(data_buf, req->src, 0, data_len, 0);

	return cmh_sm3_submit_final(req, data_buf, data_len);
}

static int cmh_sm3_export(struct ahash_request *req, void *out)
{
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_sm3_export_state *state = out;

	/*
	 * Zero the whole exported state first: the struct may carry padding,
	 * so without this the padding would leak kernel memory to user space
	 * through the ahash export.
	 */
	memset(state, 0, sizeof(*state));

	if (rctx->hw_started && rctx->has_checkpoint)
		memcpy(state->checkpoint, rctx->checkpoint, SM3_CONTEXT_SIZE);

	state->hw_started = rctx->hw_started;

	return 0;
}

static int cmh_sm3_import(struct ahash_request *req, const void *in)
{
	struct cmh_sm3_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_sm3_export_state *state = in;

	memset(rctx, 0, sizeof(*rctx));

	rctx->hw_started = state->hw_started;

	if (state->hw_started) {
		memcpy(rctx->checkpoint, state->checkpoint, SM3_CONTEXT_SIZE);
		rctx->has_checkpoint = 1;
	}

	return 0;
}

/* Registration */

static struct ahash_alg cmh_sm3_ahash_alg = {
	.init    = cmh_sm3_init,
	.update  = cmh_sm3_update,
	.finup   = cmh_sm3_finup,
	.digest  = cmh_sm3_digest,
	.export  = cmh_sm3_export,
	.import  = cmh_sm3_import,

	.halg = {
		.digestsize = CMH_SM3_DIGEST_SIZE,
		.statesize  = sizeof(struct cmh_sm3_export_state),
		.base = {
			.cra_name        = "sm3",
			.cra_driver_name = "rambus-cmh-sm3",
			.cra_priority    = 300,
			.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
					   CRYPTO_ALG_NO_FALLBACK |
					   CRYPTO_ALG_ASYNC |
					   CRYPTO_AHASH_ALG_BLOCK_ONLY,
			.cra_blocksize   = CMH_SM3_BLOCK_SIZE,
			.cra_ctxsize     = 0,
			.cra_reqsize     = sizeof(struct cmh_sm3_reqctx),
			.cra_module      = THIS_MODULE,
		},
	},
};

/**
 * cmh_sm3_register() - Register SM3 hash algorithm with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_sm3_register(void)
{
	int ret;

	if (!cmh_core_present(CMH_CORE_SM3))
		return 0;

	ret = crypto_register_ahash(&cmh_sm3_ahash_alg);
	if (ret) {
		dev_err(cmh_dev(), "sm3: failed to register cmh-sm3 (rc=%d)\n",
			ret);
		return ret;
	}

	return 0;
}

/**
 * cmh_sm3_unregister() - Unregister SM3 hash algorithm from the crypto framework
 */
void cmh_sm3_unregister(void)
{
	if (!cmh_core_present(CMH_CORE_SM3))
		return;

	crypto_unregister_ahash(&cmh_sm3_ahash_alg);
}
