// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API KMAC Driver
 *
 * Registers KMAC-128 and KMAC-256 as keyed ahash algorithms using the
 * CMH Hash Core (HC) via HC_CMD_KMAC.
 *
 * KMAC (NIST SP 800-185) is a keyed variant of cSHAKE.  The function
 * name N is always "KMAC" (hardcoded by the CMH eSW).  The user sets:
 *   - A key via .setkey() (raw bytes + optional S)
 *   - An optional customization string S via the setkey blob
 *
 * setkey blob format:
 *   struct kmac_key_param { __be32 keylen; __be32 s_len; };
 *   blob: kmac_key_param || key[keylen] || S[s_len]
 *
 * Uses the same self-contained transaction model as cmh_hmac.c:
 *   .setkey() -> store raw key (+ S)
 *   .init()   -> software-only
 *   .update() -> software-only (accumulate chunks)
 *   .final()  -> [SYS_CMD_WRITE] + HC_CMD_KMAC [+ inline S] +
 *               [GATHER] + FINAL + FLUSH
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

#include "cmh_kmac.h"
#include "cmh_vcq.h"
#include "cmh_hc_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/*
 * Maximum data that can be accumulated across .update() calls.
 * The CMH eSW rejects HC_CMD_SAVE when ctx->outlen != 0, which is
 * always the case for KMAC (eip59_hc_kmac() sets ctx->outlen for
 * right_encode(outlen) at finalization).  All data must be buffered
 * in kernel memory and submitted atomically in .final().
 *
 * The CMH eSW does not serialize outlen into the external save
 * context, so HC_CMD_SAVE fails for KMAC mode.
 */
#define KMAC_MAX_DATA		(64 * 1024)

/* Algorithm Table */

struct cmh_kmac_alg_info {
	u32         hc_algo;
	u32         digest_size;
	const char *alg_name;
	const char *drv_name;
};

static const struct cmh_kmac_alg_info cmh_kmac_algs_info[] = {
	{
		.hc_algo     = HC_ALGO_SHAKE128,
		.digest_size = CMH_SHAKE128_DIGEST_SIZE,
		.alg_name    = "kmac128",
		.drv_name    = "cri-cmh-kmac128",
	},
	{
		.hc_algo     = HC_ALGO_SHAKE256,
		.digest_size = CMH_SHAKE256_DIGEST_SIZE,
		.alg_name    = "kmac256",
		.drv_name    = "cri-cmh-kmac256",
	},
};

#define CMH_KMAC_ALG_COUNT  ARRAY_SIZE(cmh_kmac_algs_info)

/* Per-Request State */

struct cmh_kmac_chunk {
	struct list_head  list;
	struct list_head  tfm_node; /* per-tfm orphan tracking */
	u32               len;
	u8                data[];
};

/*
 * Max payload slots for KMAC:
 *   SYS_CMD_WRITE (1) + KMAC (1) + inline S (3 max) + GATHER (1) +
 *   FINAL (1) + FLUSH (1) = 8
 */
#define CMH_KMAC_MAX_PAYLOAD   9
#define CMH_KMAC_MAX_PACKED    (CMH_KMAC_MAX_PAYLOAD * 2)

struct cmh_kmac_reqctx {
	const struct cmh_kmac_alg_info *info;
	int                             error;
	struct list_head                chunks;
	u32                             num_chunks;
	u32                             total_len;
	/* DMA state for async final */
	dma_addr_t                      digest_dma;
	dma_addr_t                      key_dma;
	u8                             *digest_buf;
	struct cmh_sg_map              *sgm;
	u32                             keylen;
	struct vcq_cmd packed[CMH_KMAC_MAX_PACKED];
};

/* Per-Transform State (carries key + S across requests) */

struct cmh_kmac_tfm_ctx {
	struct cmh_key_ctx key;
	u8  *custom;        /* S (customization string), NULL if empty */
	u32  custom_len;
	spinlock_t         chunk_lock;  /* protects all_chunks */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
};

/* VCQ Builders (KMAC-specific; shared builders in cmh_hc_abi.h / cmh_vcq.h) */

static void vcq_add_hc_kmac(struct vcq_cmd *slot, u32 core_id, u64 key_ref, u32 keylen,
			    u32 customlen, u32 algo, u32 outlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_KMAC);
	slot->hwc.hc.cmd_kmac.key = key_ref;
	slot->hwc.hc.cmd_kmac.custom = 0;  /* inline */
	slot->hwc.hc.cmd_kmac.keylen = keylen;
	slot->hwc.hc.cmd_kmac.customlen = customlen;
	slot->hwc.hc.cmd_kmac.algo = algo;
	slot->hwc.hc.cmd_kmac.outlen = outlen;
}

/* Request Context Cleanup */

static void cmh_kmac_free_chunks(struct cmh_kmac_reqctx *rctx,
				 struct cmh_kmac_tfm_ctx *tctx)
{
	struct cmh_kmac_chunk *chunk, *tmp;

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

static struct cmh_sg_map *
cmh_kmac_build_sg(struct cmh_kmac_reqctx *rctx, gfp_t gfp)
{
	struct cmh_dma_buf *bufs;
	struct cmh_kmac_chunk *chunk;
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

struct cmh_kmac_alg_drv {
	struct ahash_alg                 alg;
	const struct cmh_kmac_alg_info  *info;
};

static const struct cmh_kmac_alg_info *
cmh_kmac_get_info(struct crypto_ahash *tfm)
{
	struct ahash_alg *alg = crypto_ahash_alg(tfm);

	return container_of(alg, struct cmh_kmac_alg_drv, alg)->info;
}

/*
 * setkey blob for KMAC (raw key path):
 *   struct kmac_key_param { __be32 keylen; __be32 s_len; };
 *   blob: kmac_key_param || key[keylen] || S[s_len]
 */
struct kmac_key_param {
	__be32 keylen;
	__be32 s_len;
};

static int cmh_kmac_setkey(struct crypto_ahash *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct cmh_kmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	/* raw key bytes with optional S */
	{
		struct kmac_key_param hdr;
		u32 raw_keylen, s_len;
		const u8 *ptr;

		if (keylen < sizeof(hdr))
			return -EINVAL;

		memcpy(&hdr, key, sizeof(hdr));
		raw_keylen = be32_to_cpu(hdr.keylen);
		s_len = be32_to_cpu(hdr.s_len);

		if (keylen != sizeof(hdr) + raw_keylen + s_len)
			return -EINVAL;

		if (raw_keylen == 0)
			return -EINVAL;

		if (s_len > HC_CSHAKE_MAX_CUSTOMLEN)
			return -EINVAL;

		ptr = key + sizeof(hdr);

		/* Store raw key */
		{
			int ret = cmh_key_setkey_raw(&tctx->key, ptr,
						     raw_keylen, CORE_ID_HC);
			if (ret)
				return ret;
		}
		ptr += raw_keylen;

		/* Store S */
		kfree(tctx->custom);
		tctx->custom = NULL;
		tctx->custom_len = 0;

		if (s_len > 0) {
			tctx->custom = kmemdup(ptr, s_len, GFP_KERNEL);
			if (!tctx->custom) {
				cmh_key_destroy(&tctx->key);
				return -ENOMEM;
			}
			tctx->custom_len = s_len;
		}

		return 0;
	}
}

static int cmh_kmac_init(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_kmac_reqctx *rctx = ahash_request_ctx(req);

	rctx->info = cmh_kmac_get_info(tfm);
	rctx->error = 0;
	INIT_LIST_HEAD(&rctx->chunks);
	rctx->num_chunks = 0;
	rctx->total_len = 0;

	return 0;
}

static int cmh_kmac_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_kmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_kmac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_kmac_chunk *chunk;
	int nents;

	if (rctx->error)
		return rctx->error;

	if (!req->nbytes)
		return 0;

	if (req->nbytes > KMAC_MAX_DATA - rctx->total_len) {
		rctx->error = -EINVAL;
		goto err_free_chunks;
	}

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
	cmh_kmac_free_chunks(rctx, tctx);
	return rctx->error;
}

static void cmh_kmac_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_kmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_kmac_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	cmh_dma_unmap_single(rctx->digest_dma, rctx->info->digest_size,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->digest_buf,
		       rctx->info->digest_size);

	kfree(rctx->digest_buf);
	rctx->digest_buf = NULL;
	cmh_dma_free_sg(rctx->sgm);
	rctx->sgm = NULL;
	cmh_kmac_free_chunks(rctx, tctx);
	cmh_complete(&req->base, error);
}

static int cmh_kmac_final(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_kmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_kmac_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_kmac_alg_info *info = rctx->info;
	struct vcq_cmd cmds[CMH_KMAC_MAX_PAYLOAD];
	struct cmh_sg_map *sgm = NULL;
	dma_addr_t digest_dma = DMA_MAPPING_ERROR, key_dma = DMA_MAPPING_ERROR;
	u8 *digest_buf;
	u64 key_ref;
	u32 key_len;
	struct core_dispatch d;
	s32 target_mbx;
	u32 core_id;
	u32 idx;
	int ret;
	gfp_t gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
		   GFP_KERNEL : GFP_ATOMIC;

	if (rctx->error) {
		ret = rctx->error;
		goto out_free;
	}

	if (tctx->key.mode == CMH_KEY_NONE) {
		ret = -ENOKEY;
		goto out_free;
	}

	if (rctx->num_chunks > 0) {
		sgm = cmh_kmac_build_sg(rctx, gfp);
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

	/* Resolve key reference */
	idx = 0;

	key_dma = tctx->key.raw.dma;
	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP, (u64)key_dma,
			  SYS_REF_NONE, tctx->key.raw.len,
			  tctx->key.raw.sys_type);
	key_ref = SYS_REF_TEMP;
	key_len = tctx->key.raw.len;
	d = cmh_core_select_instance(CMH_CORE_HC);

	target_mbx = d.mbx_idx;

	core_id = d.core_id;

	{
		u32 span;

		vcq_add_hc_kmac(&cmds[idx], core_id, key_ref, key_len,
				tctx->custom_len, info->hc_algo,
				info->digest_size);

		/* Add inline S data after the KMAC slot */
		span = vcq_add_inline_data(&cmds[idx], tctx->custom,
					   tctx->custom_len);
		idx += span;
	}

	if (sgm)
		vcq_add_hc_gather(&cmds[idx++], core_id, (u64)sgm->items_dma,
				  HC_CMD_UPDATE);

	vcq_add_hc_final(&cmds[idx++], core_id, (u64)digest_dma, info->digest_size);
	vcq_add_flush(&cmds[idx++], core_id);

	rctx->digest_buf = digest_buf;
	rctx->digest_dma = digest_dma;
	rctx->sgm = sgm;

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_KMAC_MAX_PACKED,
					    target_mbx,
					    cmh_kmac_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_cleanup_all;

	return -EINPROGRESS;

out_cleanup_all:
	cmh_dma_unmap_single(digest_dma, info->digest_size,
			     DMA_FROM_DEVICE);
out_free_digest:
	kfree(digest_buf);

out_free_sg:
	cmh_dma_free_sg(sgm);

out_free:
	cmh_kmac_free_chunks(rctx, tctx);
	return ret;
}

static int cmh_kmac_finup(struct ahash_request *req)
{
	int ret;

	ret = cmh_kmac_update(req);
	if (ret)
		return ret;

	return cmh_kmac_final(req);
}

static int cmh_kmac_digest(struct ahash_request *req)
{
	int ret;

	ret = cmh_kmac_init(req);
	if (ret)
		return ret;

	return cmh_kmac_finup(req);
}

static int cmh_kmac_export(struct ahash_request *req, void *out)
{
	return -EOPNOTSUPP;
}

static int cmh_kmac_import(struct ahash_request *req, const void *in)
{
	return -EOPNOTSUPP;
}

/* Transform init/exit */

static int cmh_kmac_cra_init(struct crypto_tfm *tfm)
{
	struct cmh_kmac_tfm_ctx *tctx = crypto_tfm_ctx(tfm);

	tctx->key.mode = CMH_KEY_NONE;
	tctx->custom = NULL;
	tctx->custom_len = 0;
	spin_lock_init(&tctx->chunk_lock);
	INIT_LIST_HEAD(&tctx->all_chunks);
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct cmh_kmac_reqctx));
	return 0;
}

static void cmh_kmac_cra_exit(struct crypto_tfm *tfm)
{
	struct cmh_kmac_tfm_ctx *tctx = crypto_tfm_ctx(tfm);
	struct cmh_kmac_chunk *chunk, *tmp;

	/* Free any orphaned chunks (e.g. testmgr export/reimport poison) */
	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(chunk, tmp, &tctx->all_chunks, tfm_node) {
		list_del(&chunk->tfm_node);
		kfree(chunk);
	}
	spin_unlock_bh(&tctx->chunk_lock);

	cmh_key_destroy(&tctx->key);
	kfree(tctx->custom);
	tctx->custom = NULL;
}

/* Registration */

static struct cmh_kmac_alg_drv cmh_kmac_drvs[CMH_KMAC_ALG_COUNT];

/**
 * cmh_kmac_register() - Register KMAC-128/256 hash algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_kmac_register(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < CMH_KMAC_ALG_COUNT; i++) {
		const struct cmh_kmac_alg_info *info =
			&cmh_kmac_algs_info[i];
		struct cmh_kmac_alg_drv *drv = &cmh_kmac_drvs[i];
		struct ahash_alg *alg = &drv->alg;

		drv->info = info;

		alg->init   = cmh_kmac_init;
		alg->update = cmh_kmac_update;
		alg->final  = cmh_kmac_final;
		alg->finup  = cmh_kmac_finup;
		alg->digest = cmh_kmac_digest;
		alg->export = cmh_kmac_export;
		alg->import = cmh_kmac_import;
		alg->setkey = cmh_kmac_setkey;

		alg->halg.digestsize = info->digest_size;
		alg->halg.statesize  = sizeof(struct cmh_kmac_reqctx);

		strscpy(alg->halg.base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->halg.base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->halg.base.cra_priority    = 300;
		alg->halg.base.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
						 CRYPTO_ALG_NO_FALLBACK |
						 CRYPTO_ALG_ASYNC |
						 CRYPTO_ALG_REQ_VIRT;
		alg->halg.base.cra_blocksize   = 1;  /* XOF/keyed XOF */
		alg->halg.base.cra_ctxsize     = sizeof(struct cmh_kmac_tfm_ctx);
		alg->halg.base.cra_init        = cmh_kmac_cra_init;
		alg->halg.base.cra_exit        = cmh_kmac_cra_exit;
		alg->halg.base.cra_module      = THIS_MODULE;

		ret = crypto_register_ahash(alg);
		if (ret) {
			dev_err(cmh_dev(), "kmac: failed to register %s (rc=%d)\n",
				info->drv_name, ret);
			while (i--)
				crypto_unregister_ahash(&cmh_kmac_drvs[i].alg);
			return ret;
		}

		dev_dbg(cmh_dev(), "kmac: registered %s (priority 300)\n",
			info->drv_name);
	}

	dev_info(cmh_dev(), "kmac: %zu algorithm(s) registered\n",
		 CMH_KMAC_ALG_COUNT);
	return 0;
}

/**
 * cmh_kmac_unregister() - Unregister KMAC hash algorithms from the crypto framework
 */
void cmh_kmac_unregister(void)
{
	unsigned int i;

	for (i = 0; i < CMH_KMAC_ALG_COUNT; i++) {
		crypto_unregister_ahash(&cmh_kmac_drvs[i].alg);
		dev_dbg(cmh_dev(), "kmac: unregistered %s\n",
			cmh_kmac_algs_info[i].drv_name);
	}

	dev_info(cmh_dev(), "kmac: cleaned up\n");
}
