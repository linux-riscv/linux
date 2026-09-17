// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API CSHAKE Driver
 *
 * Registers cSHAKE-128 and cSHAKE-256 as ahash algorithms using the
 * CMH Hash Core (HC) via HC_CMD_CSHAKE.
 *
 * CSHAKE (NIST SP 800-185) extends SHAKE with two domain separation
 * parameters: function name N and customization string S.  When both
 * are empty, cSHAKE reduces to plain SHAKE -- the driver falls back to
 * HC_CMD_INIT in that case (per SP 800-185 S6.2).
 *
 * N and S are set via .setkey() using a self-describing binary header
 * (matching the upstream authenc precedent):
 *
 *   struct cshake_cfg { __be32 n_len; __be32 s_len; };
 *   setkey blob: cshake_cfg || N[n_len] || S[s_len]
 *
 * If .setkey() is never called, the driver defaults to plain SHAKE
 * (N="" S="").  .setkey() is per-tfm, not per-request.
 *
 * N is embedded inline in the HC_CMD_CSHAKE struct (max 36 bytes).
 * S is passed as VCQ inline data following the command slot (multi-span).
 *
 * Uses the same streaming transaction model as cmh_hash.c.  cSHAKE is a
 * sponge XOF, so cra_blocksize is 1 (the Keccak rate 168/136 exceeds
 * MAX_ALGAPI_BLOCKSIZE).  With CRYPTO_AHASH_ALG_BLOCK_ONLY and blocksize
 * 1 the Crypto API holds nothing back: .update() absorbs the whole
 * chunk and the HC core buffers any sub-rate remainder in its SAVEd
 * context across SAVE/RESTORE, so cSHAKE hashes and clones at any length
 * with bounded kernel memory.
 *   .init()   -> software-only
 *   .update() -> [first: CSHAKE(+S) | resume: CSHAKE(+S)/INIT + RESTORE]
 *                + UPDATE(all data) + SAVE + FLUSH
 *   .finup()  -> [first: CSHAKE(+S) | resume: CSHAKE(+S)/INIT + RESTORE]
 *                [+ UPDATE(residual)] + FINAL + FLUSH (also serves .final)
 *   .export()/.import() -> serialise the HC checkpoint only;
 *                the API appends its own partial-block buffer
 *
 * The cSHAKE prefix (function name N, customization string S) is
 * absorbed once by HC_CMD_CSHAKE on the first submission (bytepad-ded to
 * a full rate block, so message absorption stays rate-aligned) and is
 * carried thereafter in the SAVEd sponge state; resume re-establishes
 * the mode (CSHAKE for keyed N/S, INIT for plain SHAKE) before
 * HC_CMD_RESTORE.  The HC core supports HC_CMD_SAVE / HC_CMD_RESTORE for
 * SHAKE/cSHAKE (outlen stays 0, unlike KMAC), which is what enables both
 * streaming and transform cloning.  This is an sg-only driver (no
 * CRYPTO_ALG_REQ_VIRT): BLOCK_ONLY buffer prepending assumes scatterlists.
 *
 * .setkey() here configures public domain-separation parameters (N, S),
 * not a secret key.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include "cmh_cshake.h"
#include "cmh_vcq.h"
#include "cmh_hc_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"

/* Algorithm Table */

struct cmh_cshake_alg_info {
	u32         hc_algo;
	u32         digest_size;
	u32         block_size;   /* cra_blocksize (XOF: 1) */
	const char *alg_name;
	const char *drv_name;
};

static const struct cmh_cshake_alg_info cmh_cshake_algs_info[] = {
	{
		.hc_algo     = HC_ALGO_SHAKE128,
		.digest_size = CMH_SHAKE128_DIGEST_SIZE,
		.block_size  = 1,   /* XOF */
		.alg_name    = "cshake128",
		.drv_name    = "rambus-cmh-cshake128",
	},
	{
		.hc_algo     = HC_ALGO_SHAKE256,
		.digest_size = CMH_SHAKE256_DIGEST_SIZE,
		.block_size  = 1,   /* XOF */
		.alg_name    = "cshake256",
		.drv_name    = "rambus-cmh-cshake256",
	},
};

#define CMH_CSHAKE_ALG_COUNT  ARRAY_SIZE(cmh_cshake_algs_info)

/* Per-Request State */

/*
 * Max payload slots for a streaming cSHAKE transaction.  Worst case is a
 * resume with the largest customization string:
 *   CSHAKE (1) + inline S (4) + RESTORE (1) + UPDATE (1) + SAVE/FINAL (1)
 *   + FLUSH (1) = 9
 */
#define CMH_CSHAKE_MAX_PAYLOAD   9
#define CMH_CSHAKE_MAX_PACKED    (CMH_CSHAKE_MAX_PAYLOAD * 2)

/* Fail the build if a large customization string would overflow cmds[]. */
static_assert(CMH_CSHAKE_MAX_PAYLOAD >=
	      1 + DIV_ROUND_UP(HC_CSHAKE_MAX_CUSTOMLEN,
			       sizeof(struct vcq_cmd)) + 4);

/*
 * Exported request state (statesize): the HC checkpoint from the last
 * SAVE.  The Crypto API appends its own partial-block buffer.  Mirrors
 * the unkeyed hash driver so cSHAKE streams and clones at any length.
 */
struct cmh_cshake_export_state {
	u8  checkpoint[HC_CONTEXT_SIZE];
	u32 hw_started;
};

/*
 * Stored in ahash_request_ctx().  The checkpoint is embedded inline
 * (not heap): the kernel ahash API has no per-request destructor, so an
 * abandoned request must not leak.
 *
 * Mapping the inline checkpoint for DMA is safe even on non-coherent
 * platforms: it is only ever mapped DMA_TO_DEVICE and its bytes are
 * frozen from dma_map_single() until the matching unmap (it is written
 * solely in the completion, after the unmap).  CPU writes to adjacent
 * fields sharing a cacheline never alter the checkpoint bytes, and a
 * TO_DEVICE unmap performs no cache invalidate; the shared-cacheline
 * hazard applies only to FROM_DEVICE buffers, which are kmalloc'd.
 */
struct cmh_cshake_reqctx {
	const struct cmh_cshake_alg_info *info;
	int    error;
	u32    hw_started;      /* non-zero after first HW submission */
	u32    has_checkpoint;  /* non-zero if checkpoint[] valid */
	u32    update_remainder; /* sub-block bytes the API must re-buffer */
	/* DMA state for the current async operation */
	dma_addr_t ckpt_dma;   /* RESTORE input */
	dma_addr_t save_dma;   /* SAVE output (update only) */
	dma_addr_t data_dma;   /* UPDATE input */
	dma_addr_t digest_dma; /* FINAL output (final/digest only) */
	u8    *save_buf;
	u8    *data_buf;
	u32    data_len;
	u8    *digest_buf;
	u8     checkpoint[HC_CONTEXT_SIZE];  /* HC context from last SAVE */
	struct vcq_cmd packed[CMH_CSHAKE_MAX_PACKED];
};

/* Per-Transform State (carries N and S across requests) */

struct cmh_cshake_tfm_ctx {
	u8  *func_name;     /* N (function name), NULL if empty */
	u32  func_name_len;
	u8  *custom;        /* S (customization string), NULL if empty */
	u32  custom_len;
};

/* VCQ Builders */

/* VCQ Builders (cSHAKE-specific; shared builders in cmh_hc_abi.h / cmh_vcq.h) */

static void vcq_add_hc_save(struct vcq_cmd *slot, u32 core_id,
			    u64 output_phys, u32 outlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_SAVE);
	slot->hwc.hc.cmd_save.output = output_phys;
	slot->hwc.hc.cmd_save.outlen = outlen;
}

static void vcq_add_hc_restore(struct vcq_cmd *slot, u32 core_id,
			       u64 input_phys, u32 inlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_RESTORE);
	slot->hwc.hc.cmd_restore.input = input_phys;
	slot->hwc.hc.cmd_restore.inlen = inlen;
}

static void vcq_add_hc_cshake(struct vcq_cmd *slot, u32 core_id, u32 algo,
			      const u8 *name, u32 namelen,
			      u32 customlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_CSHAKE);
	slot->hwc.hc.cmd_cshake.custom = 0;  /* inline -- CMH eSW reads from next slot(s) */
	slot->hwc.hc.cmd_cshake.customlen = customlen;
	slot->hwc.hc.cmd_cshake.algo = algo;
	slot->hwc.hc.cmd_cshake.namelen = namelen;
	if (namelen > 0 && name)
		memcpy(slot->hwc.hc.cmd_cshake.name, name,
		       min_t(u32, namelen, HC_CSHAKE_MAX_NAMELEN));
}

/* Add an HC_CMD_UPDATE entry */
static void vcq_add_hc_update(struct vcq_cmd *slot, u32 core_id, u64 input_phys, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_UPDATE);
	slot->hwc.hc.cmd_update.input = input_phys;
	slot->hwc.hc.cmd_update.inlen = len;
}

/*
 * Emit the HC prologue that (re-)establishes the sponge mode before an
 * UPDATE and the trailing SAVE/FINAL:
 *   cSHAKE (N/S set): CSHAKE [+ inline S]
 *   plain SHAKE:      INIT
 * followed by RESTORE when resuming a saved context.  The mode command
 * is re-issued on resume too: the eSW RESTORE rejects an algo_mode
 * mismatch, and cSHAKE uses a distinct mode from INIT.  RESTORE then
 * overwrites the freshly re-absorbed prefix with the saved sponge state.
 * Returns the next free slot index.
 */
static u32 cmh_cshake_emit_prologue(struct vcq_cmd *cmds, u32 idx,
				    const struct core_dispatch *d,
				    const struct cmh_cshake_reqctx *rctx,
				    const struct cmh_cshake_tfm_ctx *tctx,
				    dma_addr_t ckpt_dma)
{
	if (tctx->func_name_len > 0 || tctx->custom_len > 0) {
		u32 span;

		vcq_add_hc_cshake(&cmds[idx], d->core_id, rctx->info->hc_algo,
				  tctx->func_name, tctx->func_name_len,
				  tctx->custom_len);
		span = vcq_add_inline_data(&cmds[idx], tctx->custom,
					   tctx->custom_len);
		idx += span;
	} else {
		vcq_add_hc_init(&cmds[idx++], d->core_id, rctx->info->hc_algo);
	}

	if (rctx->has_checkpoint)
		vcq_add_hc_restore(&cmds[idx++], d->core_id, (u64)ckpt_dma,
				   HC_CONTEXT_SIZE);

	return idx;
}

/* Reset per-request state (no heap held between operations). */
static void cmh_cshake_free_reqctx(struct cmh_cshake_reqctx *rctx)
{
	rctx->has_checkpoint = 0;
}

/* VCQ Packing + Submit */

/* ahash Operations */

struct cmh_cshake_alg_drv {
	struct ahash_alg                   alg;
	const struct cmh_cshake_alg_info  *info;
};

static const struct cmh_cshake_alg_info *
cmh_cshake_get_info(struct crypto_ahash *tfm)
{
	struct ahash_alg *alg = crypto_ahash_alg(tfm);

	return container_of(alg, struct cmh_cshake_alg_drv, alg)->info;
}

/*
 * .setkey() -- parse N and S from the self-describing cshake_cfg header.
 *
 * Blob format: cshake_cfg { __be32 n_len; __be32 s_len; } || N || S
 * If never called, the driver defaults to plain SHAKE (N="" S="").
 */
struct cshake_cfg {
	__be32 n_len;
	__be32 s_len;
};

static int cmh_cshake_setkey(struct crypto_ahash *tfm, const u8 *key,
			     unsigned int keylen)
{
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cshake_cfg cfg;
	u32 n_len, s_len;
	const u8 *ptr;

	if (keylen < sizeof(cfg))
		return -EINVAL;

	memcpy(&cfg, key, sizeof(cfg));
	n_len = be32_to_cpu(cfg.n_len);
	s_len = be32_to_cpu(cfg.s_len);

	if (keylen != sizeof(cfg) + n_len + s_len)
		return -EINVAL;

	if (n_len > HC_CSHAKE_MAX_NAMELEN)
		return -EINVAL;

	if (s_len > HC_CSHAKE_MAX_CUSTOMLEN)
		return -EINVAL;

	/*
	 * Free previous N and S.  Unlocked against a concurrent .update()/
	 * .final() that reads them: the crypto API does not issue setkey
	 * concurrently with an in-flight request on the same tfm, and the
	 * only frontend that allowed that race (AF_ALG setsockopt vs I/O)
	 * is not built on this kernel.
	 */
	kfree(tctx->func_name);
	kfree(tctx->custom);
	tctx->func_name = NULL;
	tctx->func_name_len = 0;
	tctx->custom = NULL;
	tctx->custom_len = 0;

	ptr = key + sizeof(cfg);

	if (n_len > 0) {
		tctx->func_name = kmemdup(ptr, n_len, GFP_KERNEL);
		if (!tctx->func_name)
			return -ENOMEM;
		tctx->func_name_len = n_len;
		ptr += n_len;
	}

	if (s_len > 0) {
		tctx->custom = kmemdup(ptr, s_len, GFP_KERNEL);
		if (!tctx->custom) {
			kfree(tctx->func_name);
			tctx->func_name = NULL;
			tctx->func_name_len = 0;
			return -ENOMEM;
		}
		tctx->custom_len = s_len;
	}

	return 0;
}

static int cmh_cshake_init(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(*rctx));
	rctx->info = cmh_cshake_get_info(tfm);

	return 0;
}

/*
 * Update completion -- runs from the threaded IRQ after SAVE.  Takes the
 * SAVEd context as the new checkpoint.
 */
static void cmh_cshake_update_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, HC_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->save_dma, HC_CONTEXT_SIZE,
			     DMA_FROM_DEVICE);
	cmh_dma_unmap_single(rctx->data_dma, rctx->data_len,
			     DMA_TO_DEVICE);

	if (!error) {
		memcpy(rctx->checkpoint, rctx->save_buf, HC_CONTEXT_SIZE);
		rctx->has_checkpoint = 1;
		rctx->hw_started = 1;
		/* Hand the API the sub-block remainder it must re-buffer. */
		error = rctx->update_remainder;
	} else {
		rctx->error = error;
	}

	kfree(rctx->save_buf);
	rctx->save_buf = NULL;
	kfree(rctx->data_buf);
	rctx->data_buf = NULL;
	rctx->data_len = 0;

	cmh_complete(&req->base, error);
}

/*
 * .update -- absorb the update data in hardware.
 *
 * cra_blocksize is 1, so the Crypto API hands over the whole update; it
 * is submitted as:
 *   [first: CSHAKE(+S) | resume: CSHAKE(+S)/INIT + RESTORE] + UPDATE +
 *   SAVE + FLUSH
 * The HC core buffers any sub-rate remainder into its SAVEd context, so
 * nothing is held back to the API (the completion returns 0).
 */
static int cmh_cshake_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	struct vcq_cmd cmds[CMH_CSHAKE_MAX_PAYLOAD];
	struct core_dispatch d;
	u32 full_len;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (rctx->error)
		return rctx->error;

	if (!req->nbytes)
		return 0;

	/* XOF (blocksize 1): absorb everything; HC buffers the sub-rate tail. */
	full_len = req->nbytes;
	rctx->update_remainder = 0;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/*
	 * Reject a single update whose linearisation would exceed the largest
	 * kmalloc: return a permanent -EMSGSIZE ("message too long") rather
	 * than a transient -ENOMEM the client would keep retrying.
	 */
	if (full_len > KMALLOC_MAX_SIZE)
		return -EMSGSIZE;

	rctx->data_buf = kmalloc(full_len, gfp | __GFP_NOWARN);
	if (!rctx->data_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(rctx->data_buf, req->src, 0, full_len, 0);

	rctx->save_buf = kzalloc(HC_CONTEXT_SIZE, gfp);
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

	rctx->save_dma = cmh_dma_map_single(rctx->save_buf, HC_CONTEXT_SIZE,
					    DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->save_dma)) {
		ret = -ENOMEM;
		goto err_unmap_data;
	}

	rctx->ckpt_dma = DMA_MAPPING_ERROR;
	if (rctx->has_checkpoint) {
		rctx->ckpt_dma = cmh_dma_map_single(rctx->checkpoint,
						    HC_CONTEXT_SIZE,
						    DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->ckpt_dma)) {
			ret = -ENOMEM;
			goto err_unmap_save;
		}
	}

	rctx->data_len = full_len;

	d = cmh_core_select_instance(CMH_CORE_HC);
	idx = cmh_cshake_emit_prologue(cmds, 0, &d, rctx, tctx,
				       rctx->ckpt_dma);

	vcq_add_hc_update(&cmds[idx++], d.core_id,
			  (u64)rctx->data_dma, full_len);
	vcq_add_hc_save(&cmds[idx++], d.core_id,
			(u64)rctx->save_dma, HC_CONTEXT_SIZE);
	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_CSHAKE_MAX_PACKED,
					    d.mbx_idx,
					    cmh_cshake_update_complete, req,
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
		cmh_dma_unmap_single(rctx->ckpt_dma, HC_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
err_unmap_save:
	cmh_dma_unmap_single(rctx->save_dma, HC_CONTEXT_SIZE,
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

/*
 * Final completion -- unmap DMA, copy digest, signal done.
 */
static void cmh_cshake_final_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, HC_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
	if (rctx->data_buf)
		cmh_dma_unmap_single(rctx->data_dma, rctx->data_len,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->digest_dma, rctx->info->digest_size,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->digest_buf,
		       rctx->info->digest_size);

	kfree(rctx->digest_buf);
	rctx->digest_buf = NULL;
	kfree(rctx->data_buf);
	rctx->data_buf = NULL;
	cmh_cshake_free_reqctx(rctx);
	cmh_complete(&req->base, error);
}

/*
 * Submit the final transaction:
 *   [first: CSHAKE(+S) | resume: INIT + RESTORE] [+ UPDATE(residual)]
 *   + FINAL + FLUSH
 *
 * @data_buf: linearised residual bytes, or NULL for empty input.
 *            Ownership transferred -- the callback frees it.
 */
static int cmh_cshake_submit_final(struct ahash_request *req,
				   u8 *data_buf, u32 data_len)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_cshake_alg_info *info = rctx->info;
	struct vcq_cmd cmds[CMH_CSHAKE_MAX_PAYLOAD];
	struct core_dispatch d;
	u32 idx;
	int ret;
	gfp_t gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
		    GFP_KERNEL : GFP_ATOMIC;

	rctx->data_buf = data_buf;
	rctx->data_len = data_len;

	rctx->digest_buf = kzalloc(info->digest_size, gfp);
	if (!rctx->digest_buf) {
		ret = -ENOMEM;
		goto err_free_data;
	}

	rctx->digest_dma = cmh_dma_map_single(rctx->digest_buf,
					      info->digest_size,
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
						    HC_CONTEXT_SIZE,
						    DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->ckpt_dma)) {
			ret = -ENOMEM;
			goto err_unmap_data;
		}
	}

	d = cmh_core_select_instance(CMH_CORE_HC);
	idx = cmh_cshake_emit_prologue(cmds, 0, &d, rctx, tctx,
				       rctx->ckpt_dma);

	if (data_buf && data_len > 0)
		vcq_add_hc_update(&cmds[idx++], d.core_id,
				  (u64)rctx->data_dma, data_len);

	vcq_add_hc_final(&cmds[idx++], d.core_id,
			 (u64)rctx->digest_dma, info->digest_size);
	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_CSHAKE_MAX_PACKED,
					    d.mbx_idx,
					    cmh_cshake_final_complete, req,
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
		cmh_dma_unmap_single(rctx->ckpt_dma, HC_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
err_unmap_data:
	if (data_buf && data_len > 0)
		cmh_dma_unmap_single(rctx->data_dma, data_len,
				     DMA_TO_DEVICE);
err_unmap_digest:
	cmh_dma_unmap_single(rctx->digest_dma, info->digest_size,
			     DMA_FROM_DEVICE);
err_free_digest:
	kfree(rctx->digest_buf);
	rctx->digest_buf = NULL;
err_free_data:
	kfree(data_buf);
	rctx->data_buf = NULL;
	/*
	 * Preserve the HC checkpoint on failure: a synchronous rejection is
	 * retryable, and for a terminal error the inline checkpoint is freed
	 * with the request context, so it never leaks.  It is cleared only in
	 * the completion after a successful final().
	 */
	return ret;
}

/*
 * .finup -- hash any remaining data and finalise in one transaction.
 * With BLOCK_ONLY the Crypto API prepends the bytes it held back, so
 * req->src already carries the full tail.  Also serves .final (nbytes
 * == 0).  Avoids ahash_def_finup(), which would clone via export/import.
 */
static int cmh_cshake_finup(struct ahash_request *req)
{
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	u32 data_len = req->nbytes;
	u8 *data_buf = NULL;
	gfp_t gfp;

	if (rctx->error)
		return rctx->error;

	if (data_len == 0)
		return cmh_cshake_submit_final(req, NULL, 0);

	/* Reject an oversized linearisation with a permanent -EMSGSIZE. */
	if (data_len > KMALLOC_MAX_SIZE)
		return -EMSGSIZE;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	data_buf = kmalloc(data_len, gfp | __GFP_NOWARN);
	if (!data_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(data_buf, req->src, 0, data_len, 0);

	return cmh_cshake_submit_final(req, data_buf, data_len);
}

static int cmh_cshake_digest(struct ahash_request *req)
{
	int ret;

	ret = cmh_cshake_init(req);
	if (ret)
		return ret;

	return cmh_cshake_finup(req);
}

/*
 * Export core -- purely software.  Serialise the HC checkpoint (if any);
 * the Crypto API appends its own partial-block buffer.  The streaming
 * .update() keeps the checkpoint current after each block.
 */
static int cmh_cshake_export(struct ahash_request *req, void *out)
{
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_cshake_export_state *state = out;

	/*
	 * Zero the whole state first: the struct may carry padding, so this
	 * avoids leaking kernel memory through the ahash export.
	 */
	memset(state, 0, sizeof(*state));

	if (rctx->hw_started)
		memcpy(state->checkpoint, rctx->checkpoint, HC_CONTEXT_SIZE);

	state->hw_started = rctx->hw_started;

	return 0;
}

/*
 * Import core -- purely software.  Restore the HC checkpoint; the next
 * .update()/final op RESTOREs it into HW.  The Crypto API restores its
 * own partial-block buffer separately.
 */
static int cmh_cshake_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_cshake_export_state *state = in;

	memset(rctx, 0, sizeof(*rctx));
	rctx->info = cmh_cshake_get_info(tfm);

	rctx->hw_started = state->hw_started;

	if (state->hw_started) {
		memcpy(rctx->checkpoint, state->checkpoint, HC_CONTEXT_SIZE);
		rctx->has_checkpoint = 1;
	}

	return 0;
}

/* Transform init/exit */

static int cmh_cshake_cra_init(struct crypto_tfm *tfm)
{
	struct cmh_cshake_tfm_ctx *tctx = crypto_tfm_ctx(tfm);

	tctx->func_name = NULL;
	tctx->func_name_len = 0;
	tctx->custom = NULL;
	tctx->custom_len = 0;
	return 0;
}

static void cmh_cshake_cra_exit(struct crypto_tfm *tfm)
{
	struct cmh_cshake_tfm_ctx *tctx = crypto_tfm_ctx(tfm);

	kfree(tctx->func_name);
	kfree(tctx->custom);
	tctx->func_name = NULL;
	tctx->custom = NULL;
}

/* Registration */

static struct cmh_cshake_alg_drv cmh_cshake_drvs[CMH_CSHAKE_ALG_COUNT];

/**
 * cmh_cshake_register() - Register cSHAKE-128/256 hash algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_cshake_register(void)
{
	unsigned int i;
	int ret;

	if (!cmh_core_present(CMH_CORE_HC))
		return 0;

	for (i = 0; i < CMH_CSHAKE_ALG_COUNT; i++) {
		const struct cmh_cshake_alg_info *info =
			&cmh_cshake_algs_info[i];
		struct cmh_cshake_alg_drv *drv = &cmh_cshake_drvs[i];
		struct ahash_alg *alg = &drv->alg;

		drv->info = info;

		alg->init   = cmh_cshake_init;
		alg->update = cmh_cshake_update;
		alg->finup  = cmh_cshake_finup;
		alg->digest = cmh_cshake_digest;
		alg->export = cmh_cshake_export;
		alg->import = cmh_cshake_import;
		alg->setkey = cmh_cshake_setkey;

		alg->halg.digestsize = info->digest_size;
		alg->halg.statesize  = sizeof(struct cmh_cshake_export_state);

		strscpy(alg->halg.base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->halg.base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->halg.base.cra_priority    = 300;
		alg->halg.base.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
						 CRYPTO_ALG_NO_FALLBACK |
						 CRYPTO_ALG_ASYNC |
						 CRYPTO_ALG_OPTIONAL_KEY |
						 CRYPTO_AHASH_ALG_BLOCK_ONLY;
		alg->halg.base.cra_blocksize   = info->block_size;  /* XOF: 1 */
		alg->halg.base.cra_ctxsize     = sizeof(struct cmh_cshake_tfm_ctx);
		alg->halg.base.cra_reqsize     = sizeof(struct cmh_cshake_reqctx);
		alg->halg.base.cra_init        = cmh_cshake_cra_init;
		alg->halg.base.cra_exit        = cmh_cshake_cra_exit;
		alg->halg.base.cra_module      = THIS_MODULE;

		ret = crypto_register_ahash(alg);
		if (ret) {
			dev_err(cmh_dev(), "cshake: failed to register %s (rc=%d)\n",
				info->drv_name, ret);
			while (i--)
				crypto_unregister_ahash(&cmh_cshake_drvs[i].alg);
			return ret;
		}

		dev_dbg(cmh_dev(), "cshake: registered %s (priority 300)\n",
			info->drv_name);
	}

	return 0;
}

/**
 * cmh_cshake_unregister() - Unregister cSHAKE hash algorithms from the crypto framework
 */
void cmh_cshake_unregister(void)
{
	unsigned int i;

	if (!cmh_core_present(CMH_CORE_HC))
		return;

	for (i = 0; i < CMH_CSHAKE_ALG_COUNT; i++) {
		crypto_unregister_ahash(&cmh_cshake_drvs[i].alg);
		dev_dbg(cmh_dev(), "cshake: unregistered %s\n",
			cmh_cshake_algs_info[i].drv_name);
	}
}
