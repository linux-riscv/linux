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
 * Uses the same self-contained transaction model as cmh_hash.c:
 *   .init()   -> software-only
 *   .update() -> software-only (accumulate chunks)
 *   .final()  -> CSHAKE [+ inline S] [+ RESTORE] [+ GATHER] + FINAL + FLUSH
 *   .export() -> CSHAKE [+ inline S] [+ RESTORE] [+ GATHER] + SAVE + FLUSH
 *   .import() -> restore HC context checkpoint (software-only)
 *
 * The HC core supports HC_CMD_SAVE / HC_CMD_RESTORE for cSHAKE mode.
 * The cSHAKE domain-separation prefix (function name N, customization
 * string S) is absorbed into the Keccak sponge state by HC_CMD_CSHAKE
 * on the first submission, and preserved through save/restore.
 * Export/import enables crypto API transform cloning.
 *
 * .setkey() here configures public domain-separation parameters (N, S),
 * not a secret key.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <linux/scatterlist.h>
#include <linux/list.h>
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
	const char *alg_name;
	const char *drv_name;
};

static const struct cmh_cshake_alg_info cmh_cshake_algs_info[] = {
	{
		.hc_algo     = HC_ALGO_SHAKE128,
		.digest_size = CMH_SHAKE128_DIGEST_SIZE,
		.alg_name    = "cshake128",
		.drv_name    = "cri-cmh-cshake128",
	},
	{
		.hc_algo     = HC_ALGO_SHAKE256,
		.digest_size = CMH_SHAKE256_DIGEST_SIZE,
		.alg_name    = "cshake256",
		.drv_name    = "cri-cmh-cshake256",
	},
};

#define CMH_CSHAKE_ALG_COUNT  ARRAY_SIZE(cmh_cshake_algs_info)

/* Per-Request State */

struct cmh_cshake_chunk {
	struct list_head  list;
	struct list_head  tfm_node; /* per-tfm orphan tracking */
	u32               len;
	u8                data[];
};

/*
 * Max payload slots for CSHAKE:
 *   CSHAKE (1) + inline S (ceil(S_len/64)) + GATHER (1) + FINAL (1) + FLUSH (1)
 * S can be up to SHAKE-128 block (168 bytes) = 3 inline slots.
 * Conservative: 1 + 3 + 1 + 1 + 1 = 7, plus headers.
 *
 * Or INIT + GATHER + FINAL + FLUSH = 4 (plain SHAKE fallback).
 */
#define CMH_CSHAKE_MAX_PAYLOAD   8
#define CMH_CSHAKE_MAX_PACKED    (CMH_CSHAKE_MAX_PAYLOAD * 2)

/*
 * Checkpoint embedded inline: the kernel ahash API has no per-request
 * destructor, so a heap-allocated checkpoint leaks if a request is
 * abandoned without .final().
 */
struct cmh_cshake_reqctx {
	const struct cmh_cshake_alg_info *info;
	int                               error;
	struct list_head                  chunks;
	u32                               num_chunks;
	u32                               total_len;
	u32                               has_checkpoint;
	u8                                checkpoint[HC_CONTEXT_SIZE];
	/* DMA state for async final */
	dma_addr_t                        digest_dma;
	dma_addr_t                        ckpt_dma;
	u8                               *digest_buf;
	struct cmh_sg_map                *sgm;
	struct vcq_cmd packed[CMH_CSHAKE_MAX_PACKED];
};

/* Per-Transform State (carries N and S across requests) */

struct cmh_cshake_tfm_ctx {
	u8  *func_name;     /* N (function name), NULL if empty */
	u32  func_name_len;
	u8  *custom;        /* S (customization string), NULL if empty */
	u32  custom_len;
	spinlock_t         chunk_lock;  /* protects all_chunks */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
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

/* Request Context Cleanup */

static void cmh_cshake_free_chunks(struct cmh_cshake_reqctx *rctx,
				   struct cmh_cshake_tfm_ctx *tctx)
{
	struct cmh_cshake_chunk *chunk, *tmp;

	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(chunk, tmp, &rctx->chunks, list) {
		list_del(&chunk->list);
		list_del(&chunk->tfm_node);
		kfree(chunk);
	}
	spin_unlock_bh(&tctx->chunk_lock);
	rctx->num_chunks = 0;
	rctx->total_len = 0;
}

static void cmh_cshake_free_reqctx(struct cmh_cshake_reqctx *rctx,
				   struct cmh_cshake_tfm_ctx *tctx)
{
	cmh_cshake_free_chunks(rctx, tctx);
	rctx->has_checkpoint = 0;
}

static struct cmh_sg_map *
cmh_cshake_build_sg(struct cmh_cshake_reqctx *rctx, gfp_t gfp)
{
	struct cmh_dma_buf *bufs;
	struct cmh_cshake_chunk *chunk;
	struct cmh_sg_map *sgm;
	u32 i;

	bufs = kcalloc(rctx->num_chunks, sizeof(*bufs), gfp);
	if (!bufs)
		return NULL;

	i = 0;
	list_for_each_entry(chunk, &rctx->chunks, list) {
		bufs[i].data = chunk->data;
		bufs[i].len = chunk->len;
		i++;
	}

	sgm = cmh_dma_build_sg(bufs, rctx->num_chunks, gfp);
	kfree(bufs);
	return sgm;
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

	/* Free previous N and S */
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

	rctx->info = cmh_cshake_get_info(tfm);
	rctx->error = 0;
	INIT_LIST_HEAD(&rctx->chunks);
	rctx->num_chunks = 0;
	rctx->total_len = 0;
	rctx->has_checkpoint = 0;

	return 0;
}

static int cmh_cshake_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_cshake_chunk *chunk;
	int nents;

	if (rctx->error)
		return rctx->error;

	if (!req->nbytes)
		return 0;

	chunk = kmalloc(sizeof(*chunk) + req->nbytes,
			req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
			GFP_KERNEL : GFP_ATOMIC);
	if (!chunk) {
		rctx->error = -ENOMEM;
		goto err_free_chunks;
	}

	chunk->len = req->nbytes;
	if (req->base.flags & CRYPTO_AHASH_REQ_VIRT) {
		memcpy(chunk->data, req->svirt, req->nbytes);
	} else {
		nents = sg_nents_for_len(req->src, req->nbytes);
		if (nents < 0 ||
		    sg_copy_to_buffer(req->src, nents,
				      chunk->data, req->nbytes) != req->nbytes) {
			kfree(chunk);
			rctx->error = -EINVAL;
			goto err_free_chunks;
		}
	}

	list_add_tail(&chunk->list, &rctx->chunks);
	spin_lock_bh(&tctx->chunk_lock);
	list_add_tail(&chunk->tfm_node, &tctx->all_chunks);
	spin_unlock_bh(&tctx->chunk_lock);
	rctx->num_chunks++;
	rctx->total_len += req->nbytes;

	return 0;

err_free_chunks:
	/*
	 * Terminal error -- free all previously accumulated chunks.
	 * The crypto API hash path does not call .final() on error,
	 * so chunks would be orphaned otherwise.
	 */
	cmh_cshake_free_chunks(rctx, tctx);
	return rctx->error;
}

static void cmh_cshake_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(rctx->ckpt_dma, HC_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->digest_dma, rctx->info->digest_size,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->digest_buf,
		       rctx->info->digest_size);

	kfree(rctx->digest_buf);
	rctx->digest_buf = NULL;
	cmh_dma_free_sg(rctx->sgm);
	rctx->sgm = NULL;
	cmh_cshake_free_reqctx(rctx, tctx);
	cmh_complete(&req->base, error);
}

static int cmh_cshake_final(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_cshake_alg_info *info = rctx->info;
	struct core_dispatch d;
	struct vcq_cmd cmds[CMH_CSHAKE_MAX_PAYLOAD];
	struct cmh_sg_map *sgm = NULL;
	dma_addr_t digest_dma = DMA_MAPPING_ERROR;
	dma_addr_t ckpt_dma = DMA_MAPPING_ERROR;
	u8 *digest_buf;
	u32 idx;
	int ret;
	gfp_t gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
		     GFP_KERNEL : GFP_ATOMIC;

	if (rctx->error) {
		ret = rctx->error;
		goto out_free;
	}

	if (rctx->num_chunks > 0) {
		sgm = cmh_cshake_build_sg(rctx, gfp);
		if (!sgm) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	digest_buf = kzalloc(info->digest_size, gfp);
	if (!digest_buf) {
		ret = -ENOMEM;
		goto out_free_sg;
	}
	digest_dma = cmh_dma_map_single(digest_buf, info->digest_size,
					DMA_FROM_DEVICE);
	if (cmh_dma_map_error(digest_dma)) {
		ret = -ENOMEM;
		goto out_free_digest;
	}

	/* Map checkpoint buffer if present (CMH eSW reads it) */
	if (rctx->has_checkpoint) {
		ckpt_dma = cmh_dma_map_single(rctx->checkpoint,
					      HC_CONTEXT_SIZE, DMA_TO_DEVICE);
		if (cmh_dma_map_error(ckpt_dma)) {
			ret = -ENOMEM;
			goto out_unmap_digest;
		}
	}

	d = cmh_core_select_instance(CMH_CORE_HC);
	idx = 0;

	if (rctx->has_checkpoint) {
		/*
		 * Resuming from a saved checkpoint (after export/import):
		 * INIT + RESTORE [+ GATHER] + FINAL + FLUSH
		 * The cSHAKE prefix (N,S) is already absorbed in the
		 * saved Keccak state -- no need to replay HC_CMD_CSHAKE.
		 */
		vcq_add_hc_init(&cmds[idx++], d.core_id, info->hc_algo);
		vcq_add_hc_restore(&cmds[idx++], d.core_id, (u64)ckpt_dma,
				   HC_CONTEXT_SIZE);
	} else {
		bool use_cshake = (tctx->func_name_len > 0 ||
				   tctx->custom_len > 0);

		if (use_cshake) {
			u32 span;

			vcq_add_hc_cshake(&cmds[idx], d.core_id,
					  info->hc_algo,
					  tctx->func_name,
					  tctx->func_name_len,
					  tctx->custom_len);
			span = vcq_add_inline_data(&cmds[idx],
						   tctx->custom,
						   tctx->custom_len);
			idx += span;
		} else {
			vcq_add_hc_init(&cmds[idx++], d.core_id,
					info->hc_algo);
		}
	}

	if (sgm)
		vcq_add_hc_gather(&cmds[idx++], d.core_id, (u64)sgm->items_dma,
				  HC_CMD_UPDATE);

	vcq_add_hc_final(&cmds[idx++], d.core_id, (u64)digest_dma, info->digest_size);
	vcq_add_flush(&cmds[idx++], d.core_id);

	rctx->digest_buf = digest_buf;
	rctx->digest_dma = digest_dma;
	rctx->ckpt_dma = ckpt_dma;
	rctx->sgm = sgm;

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_CSHAKE_MAX_PACKED,
					    d.mbx_idx,
					    cmh_cshake_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_cleanup_all;

	return -EINPROGRESS;

out_cleanup_all:
	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(ckpt_dma, HC_CONTEXT_SIZE,
				     DMA_TO_DEVICE);
out_unmap_digest:
	cmh_dma_unmap_single(digest_dma, info->digest_size,
			     DMA_FROM_DEVICE);
out_free_digest:
	kfree(digest_buf);

out_free_sg:
	cmh_dma_free_sg(sgm);

out_free:
	cmh_cshake_free_reqctx(rctx, tctx);
	return ret;
}

static int cmh_cshake_finup(struct ahash_request *req)
{
	int ret;

	ret = cmh_cshake_update(req);
	if (ret)
		return ret;

	return cmh_cshake_final(req);
}

static int cmh_cshake_digest(struct ahash_request *req)
{
	int ret;

	ret = cmh_cshake_init(req);
	if (ret)
		return ret;

	return cmh_cshake_finup(req);
}

static int cmh_cshake_export(struct ahash_request *req, void *out)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_cshake_alg_info *info = rctx->info;
	struct core_dispatch d;
	struct vcq_cmd cmds[CMH_CSHAKE_MAX_PAYLOAD];
	struct cmh_sg_map *sgm = NULL;
	dma_addr_t save_dma = DMA_MAPPING_ERROR;
	dma_addr_t ckpt_dma = DMA_MAPPING_ERROR;
	u8 *save_buf;
	u32 idx;
	int ret;

	if (rctx->num_chunks > 0) {
		sgm = cmh_cshake_build_sg(rctx, GFP_KERNEL);
		if (!sgm)
			return -ENOMEM;
	}

	save_buf = kzalloc(HC_CONTEXT_SIZE, GFP_KERNEL);
	if (!save_buf) {
		cmh_dma_free_sg(sgm);
		return -ENOMEM;
	}
	save_dma = cmh_dma_map_single(save_buf, HC_CONTEXT_SIZE,
				      DMA_FROM_DEVICE);
	if (cmh_dma_map_error(save_dma)) {
		kfree(save_buf);
		cmh_dma_free_sg(sgm);
		return -ENOMEM;
	}

	/* Map checkpoint buffer if present (CMH eSW reads it) */
	if (rctx->has_checkpoint) {
		ckpt_dma = cmh_dma_map_single(rctx->checkpoint,
					      HC_CONTEXT_SIZE, DMA_TO_DEVICE);
		if (cmh_dma_map_error(ckpt_dma)) {
			cmh_dma_unmap_single(save_dma, HC_CONTEXT_SIZE,
					     DMA_FROM_DEVICE);
			kfree(save_buf);
			cmh_dma_free_sg(sgm);
			return -ENOMEM;
		}
	}

	d = cmh_core_select_instance(CMH_CORE_HC);
	idx = 0;

	if (rctx->has_checkpoint) {
		/*
		 * Resuming from a saved checkpoint:
		 * INIT + RESTORE [+ GATHER] + SAVE + FLUSH
		 */
		vcq_add_hc_init(&cmds[idx++], d.core_id, info->hc_algo);
		vcq_add_hc_restore(&cmds[idx++], d.core_id, (u64)ckpt_dma,
				   HC_CONTEXT_SIZE);
	} else {
		bool use_cshake = (tctx->func_name_len > 0 ||
				   tctx->custom_len > 0);

		if (use_cshake) {
			u32 span;

			vcq_add_hc_cshake(&cmds[idx], d.core_id,
					  info->hc_algo,
					  tctx->func_name,
					  tctx->func_name_len,
					  tctx->custom_len);
			span = vcq_add_inline_data(&cmds[idx],
						   tctx->custom,
						   tctx->custom_len);
			idx += span;
		} else {
			vcq_add_hc_init(&cmds[idx++], d.core_id,
					info->hc_algo);
		}
	}

	if (sgm)
		vcq_add_hc_gather(&cmds[idx++], d.core_id, (u64)sgm->items_dma,
				  HC_CMD_UPDATE);

	vcq_add_hc_save(&cmds[idx++], d.core_id, (u64)save_dma,
			HC_CONTEXT_SIZE);
	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit(cmds, idx, rctx->packed, CMH_CSHAKE_MAX_PACKED,
				      d.mbx_idx);

	/* Unmap before CPU read */
	if (rctx->has_checkpoint)
		cmh_dma_unmap_single(ckpt_dma, HC_CONTEXT_SIZE, DMA_TO_DEVICE);
	cmh_dma_unmap_single(save_dma, HC_CONTEXT_SIZE, DMA_FROM_DEVICE);

	if (!ret) {
		memcpy(out, save_buf, HC_CONTEXT_SIZE);
		/* Checkpoint now represents all accumulated state */
		memcpy(rctx->checkpoint, save_buf, HC_CONTEXT_SIZE);
		rctx->has_checkpoint = 1;
		/* Accumulated chunks are now captured in checkpoint */
		cmh_cshake_free_chunks(rctx, tctx);
	}

	kfree(save_buf);
	cmh_dma_free_sg(sgm);
	return ret;
}

static int cmh_cshake_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_cshake_reqctx *rctx = ahash_request_ctx(req);

	rctx->info = cmh_cshake_get_info(tfm);
	rctx->error = 0;
	INIT_LIST_HEAD(&rctx->chunks);
	rctx->num_chunks = 0;
	rctx->total_len = 0;

	memcpy(rctx->checkpoint, in, HC_CONTEXT_SIZE);
	rctx->has_checkpoint = 1;

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
	spin_lock_init(&tctx->chunk_lock);
	INIT_LIST_HEAD(&tctx->all_chunks);
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct cmh_cshake_reqctx));
	return 0;
}

static void cmh_cshake_cra_exit(struct crypto_tfm *tfm)
{
	struct cmh_cshake_tfm_ctx *tctx = crypto_tfm_ctx(tfm);
	struct cmh_cshake_chunk *chunk, *tmp;

	/* Free any orphaned chunks (e.g. testmgr export/reimport poison) */
	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(chunk, tmp, &tctx->all_chunks, tfm_node) {
		list_del(&chunk->tfm_node);
		kfree(chunk);
	}
	spin_unlock_bh(&tctx->chunk_lock);

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

	for (i = 0; i < CMH_CSHAKE_ALG_COUNT; i++) {
		const struct cmh_cshake_alg_info *info =
			&cmh_cshake_algs_info[i];
		struct cmh_cshake_alg_drv *drv = &cmh_cshake_drvs[i];
		struct ahash_alg *alg = &drv->alg;

		drv->info = info;

		alg->init   = cmh_cshake_init;
		alg->update = cmh_cshake_update;
		alg->final  = cmh_cshake_final;
		alg->finup  = cmh_cshake_finup;
		alg->digest = cmh_cshake_digest;
		alg->export = cmh_cshake_export;
		alg->import = cmh_cshake_import;
		alg->setkey = cmh_cshake_setkey;

		alg->halg.digestsize = info->digest_size;
		alg->halg.statesize  = HC_CONTEXT_SIZE;

		strscpy(alg->halg.base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->halg.base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->halg.base.cra_priority    = 300;
		alg->halg.base.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
						 CRYPTO_ALG_NO_FALLBACK |
						 CRYPTO_ALG_ASYNC |
						 CRYPTO_ALG_OPTIONAL_KEY |
						 CRYPTO_ALG_REQ_VIRT;
		alg->halg.base.cra_blocksize   = 1;  /* XOF */
		alg->halg.base.cra_ctxsize     = sizeof(struct cmh_cshake_tfm_ctx);
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

	dev_info(cmh_dev(), "cshake: %zu algorithm(s) registered\n",
		 CMH_CSHAKE_ALG_COUNT);
	return 0;
}

/**
 * cmh_cshake_unregister() - Unregister cSHAKE hash algorithms from the crypto framework
 */
void cmh_cshake_unregister(void)
{
	unsigned int i;

	for (i = 0; i < CMH_CSHAKE_ALG_COUNT; i++) {
		crypto_unregister_ahash(&cmh_cshake_drvs[i].alg);
		dev_dbg(cmh_dev(), "cshake: unregistered %s\n",
			cmh_cshake_algs_info[i].drv_name);
	}

	dev_info(cmh_dev(), "cshake: cleaned up\n");
}
