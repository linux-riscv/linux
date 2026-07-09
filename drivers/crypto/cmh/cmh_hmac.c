// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API HMAC Driver
 *
 * Registers HMAC ahash algorithms with the Linux crypto subsystem.
 * Supports HMAC-SHA-2 (224/256/384/512) and HMAC-SHA-3 (224/256/384/512)
 * using the CMH Hash Core (HC) via HC_CMD_HMAC.
 *
 * Uses the same self-contained transaction model as cmh_hash.c:
 *   .setkey() -> store raw key bytes
 *   .init()   -> software-only: initialize per-request context
 *   .update() -> software-only: copy SG data into per-call chunk
 *   .final()  -> [SYS_CMD_WRITE] + HC_CMD_HMAC + [GATHER] + FINAL + FLUSH
 *
 * Raw-key atomicity: SYS_CMD_WRITE to SYS_REF_TEMP is packed into
 * the same VCQ as HC_CMD_HMAC (see cmh_key.h for details).
 *
 * ahash .export()/.import() (state cloning): supported at the
 * software accumulation level only.  The HW hash core does NOT
 * support save/restore of intermediate HMAC state (SHA3 sponge
 * invertibility, SHA2 blocked for consistency).  Since this driver
 * accumulates all input data in kernel memory before submitting
 * atomically in .final(), export/import simply serializes the
 * input queue -- no keying material or HW state is exposed.
 *
 * All HMAC data is accumulated in kernel memory and capped at
 * HMAC_MAX_DATA (64 KB).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_hmac.h"
#include "cmh_vcq.h"
#include "cmh_hc_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/*
 * Maximum data that can be accumulated across .update() calls.
 * HMAC save/restore is intentionally unsupported (see file header),
 * so all data must be buffered in kernel memory and submitted
 * atomically in .final().  This cap prevents unbounded allocation.
 */
#define HMAC_MAX_DATA		(64 * 1024)

/* Algorithm Table */

struct cmh_hmac_alg_info {
	u32         hc_algo;        /* HC_ALGO_* */
	u32         digest_size;    /* bytes */
	u32         block_size;     /* cra_blocksize */
	const char *alg_name;       /* Linux crypto name: "hmac(sha256)" */
	const char *drv_name;       /* driver name: "cri-cmh-hmac-sha256" */
};

static const struct cmh_hmac_alg_info cmh_hmac_algs_info[] = {
	/* HMAC-SHA-2 family */
	{
		.hc_algo     = HC_ALGO_SHA2_224,
		.digest_size = CMH_SHA224_DIGEST_SIZE,
		.block_size  = 64,
		.alg_name    = "hmac(sha224)",
		.drv_name    = "cri-cmh-hmac-sha224",
	},
	{
		.hc_algo     = HC_ALGO_SHA2_256,
		.digest_size = CMH_SHA256_DIGEST_SIZE,
		.block_size  = 64,
		.alg_name    = "hmac(sha256)",
		.drv_name    = "cri-cmh-hmac-sha256",
	},
	{
		.hc_algo     = HC_ALGO_SHA2_384,
		.digest_size = CMH_SHA384_DIGEST_SIZE,
		.block_size  = 128,
		.alg_name    = "hmac(sha384)",
		.drv_name    = "cri-cmh-hmac-sha384",
	},
	{
		.hc_algo     = HC_ALGO_SHA2_512,
		.digest_size = CMH_SHA512_DIGEST_SIZE,
		.block_size  = 128,
		.alg_name    = "hmac(sha512)",
		.drv_name    = "cri-cmh-hmac-sha512",
	},
	/* HMAC-SHA-3 family */
	{
		.hc_algo     = HC_ALGO_SHA3_224,
		.digest_size = CMH_SHA3_224_DIGEST_SIZE,
		.block_size  = 144,
		.alg_name    = "hmac(sha3-224)",
		.drv_name    = "cri-cmh-hmac-sha3-224",
	},
	{
		.hc_algo     = HC_ALGO_SHA3_256,
		.digest_size = CMH_SHA3_256_DIGEST_SIZE,
		.block_size  = 136,
		.alg_name    = "hmac(sha3-256)",
		.drv_name    = "cri-cmh-hmac-sha3-256",
	},
	{
		.hc_algo     = HC_ALGO_SHA3_384,
		.digest_size = CMH_SHA3_384_DIGEST_SIZE,
		.block_size  = 104,
		.alg_name    = "hmac(sha3-384)",
		.drv_name    = "cri-cmh-hmac-sha3-384",
	},
	{
		.hc_algo     = HC_ALGO_SHA3_512,
		.digest_size = CMH_SHA3_512_DIGEST_SIZE,
		.block_size  = 72,
		.alg_name    = "hmac(sha3-512)",
		.drv_name    = "cri-cmh-hmac-sha3-512",
	},
};

#define CMH_HMAC_ALG_COUNT  ARRAY_SIZE(cmh_hmac_algs_info)

/* Per-Request State */

struct cmh_hmac_chunk {
	struct list_head  list;
	struct list_head  tfm_node; /* per-tfm orphan tracking */
	u32               len;
	u8                data[];
};

/*
 * Maximum payload commands any HMAC transaction can produce:
 *   [SYS_CMD_WRITE] + HC_CMD_HMAC + [GATHER] + FINAL + FLUSH = 5
 * Worst-case packed output (stride=7, 1 payload per VCQ):
 *   5 VCQs x 2 entries = 10
 */
#define CMH_HMAC_MAX_PAYLOAD    5
#define CMH_HMAC_MAX_PACKED     (CMH_HMAC_MAX_PAYLOAD * 2)

struct cmh_hmac_reqctx {
	const struct cmh_hmac_alg_info *info;
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
	struct vcq_cmd packed[CMH_HMAC_MAX_PACKED];
};

/* Flat state for export/import -- holds accumulated input data only */
struct cmh_hmac_export_state {
	u32 total_len;
	u8  data[];
};

/*
 * Flat state buffer for export/import.  The CMH hash core does not
 * support save/restore of intermediate HMAC state, so this driver
 * accumulates input in SW and serialises the buffer on export.
 *
 * PAGE_SIZE (4096) caps the exportable accumulated-data window.
 * Full-range export (up to HMAC_MAX_DATA = 64 KB) is not feasible
 * because the crypto subsystem pre-allocates statesize bytes per
 * request.  Export returns -EINVAL if the caller has accumulated
 * more than CMH_HMAC_EXPORT_MAX.
 */
#define CMH_HMAC_STATE_SIZE 4096
#define CMH_HMAC_EXPORT_MAX (CMH_HMAC_STATE_SIZE - sizeof(struct cmh_hmac_export_state))

/* Per-Transform State (carries key across requests) */

struct cmh_hmac_tfm_ctx {
	struct cmh_key_ctx key;
	spinlock_t         chunk_lock;  /* protects all_chunks */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
};

/* VCQ Builders (HMAC-specific; shared builders in cmh_hc_abi.h / cmh_vcq.h) */

/* Add an HC_CMD_HMAC entry */
static void vcq_add_hc_hmac(struct vcq_cmd *slot, u32 core_id, u64 key_ref,
			    u32 keylen, u32 algo)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_HMAC);
	slot->hwc.hc.cmd_hmac.key = key_ref;
	slot->hwc.hc.cmd_hmac.keylen = keylen;
	slot->hwc.hc.cmd_hmac.algo = algo;
}

/* Request Context Cleanup */

static void cmh_hmac_free_chunks(struct cmh_hmac_reqctx *rctx,
				 struct cmh_hmac_tfm_ctx *tctx)
{
	struct cmh_hmac_chunk *chunk, *tmp;

	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(chunk, tmp, &rctx->chunks, list) {
		list_del(&chunk->list);
		list_del(&chunk->tfm_node);
		kfree_sensitive(chunk);
	}
	spin_unlock_bh(&tctx->chunk_lock);
	rctx->num_chunks = 0;
	rctx->total_len = 0;
}

/*
 * Build a DMA-mapped CMH eSW scatter-gather chain from accumulated chunks.
 */
static struct cmh_sg_map *
cmh_hmac_build_sg(struct cmh_hmac_reqctx *rctx, gfp_t gfp)
{
	struct cmh_dma_buf *bufs;
	struct cmh_hmac_chunk *chunk;
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

struct cmh_hmac_alg_drv {
	struct ahash_alg                  alg;
	const struct cmh_hmac_alg_info   *info;
};

static const struct cmh_hmac_alg_info *
cmh_hmac_get_info(struct crypto_ahash *tfm)
{
	struct ahash_alg *alg = crypto_ahash_alg(tfm);

	return container_of(alg, struct cmh_hmac_alg_drv, alg)->info;
}

static int cmh_hmac_setkey(struct crypto_ahash *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct cmh_hmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);

	return cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_HC);
}

static int cmh_hmac_init(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hmac_reqctx *rctx = ahash_request_ctx(req);

	rctx->info = cmh_hmac_get_info(tfm);
	rctx->error = 0;
	INIT_LIST_HEAD(&rctx->chunks);
	rctx->num_chunks = 0;
	rctx->total_len = 0;

	return 0;
}

static int cmh_hmac_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_hmac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_hmac_chunk *chunk;
	int nents;

	if (rctx->error)
		return rctx->error;

	if (!req->nbytes)
		return 0;

	if (req->nbytes > HMAC_MAX_DATA - rctx->total_len) {
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
			kfree_sensitive(chunk);
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
	 * The crypto API hash path does not call .final()
	 * on error, and hash_sock_destruct has no per-request
	 * destructor, so chunks would be orphaned otherwise.
	 */
	cmh_hmac_free_chunks(rctx, tctx);
	return rctx->error;
}

static void cmh_hmac_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_hmac_reqctx *rctx = ahash_request_ctx(req);

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
	cmh_hmac_free_chunks(rctx, tctx);
	cmh_complete(&req->base, error);
}

static int cmh_hmac_final(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_hmac_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_hmac_alg_info *info = rctx->info;
	struct vcq_cmd cmds[CMH_HMAC_MAX_PAYLOAD];
	struct cmh_sg_map *sgm = NULL;
	dma_addr_t digest_dma = DMA_MAPPING_ERROR, key_dma = DMA_MAPPING_ERROR;
	u8 *digest_buf;
	u64 key_ref;
	u32 keylen;
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
		sgm = cmh_hmac_build_sg(rctx, gfp);
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

	/*
	 * Raw key: pack SYS_CMD_WRITE(SYS_REF_TEMP) into the
	 * same VCQ so the key write + HMAC are atomic.
	 */
	key_dma = tctx->key.raw.dma;
	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP, (u64)key_dma,
			  SYS_REF_NONE, tctx->key.raw.len,
			  tctx->key.raw.sys_type);
	key_ref = SYS_REF_TEMP;
	keylen = tctx->key.raw.len;
	d = cmh_core_select_instance(CMH_CORE_HC);

	target_mbx = d.mbx_idx;

	core_id = d.core_id;

	vcq_add_hc_hmac(&cmds[idx++], core_id, key_ref, keylen, info->hc_algo);

	if (sgm)
		vcq_add_hc_gather(&cmds[idx++], core_id, (u64)sgm->items_dma,
				  HC_CMD_UPDATE);

	vcq_add_hc_final(&cmds[idx++], core_id, (u64)digest_dma, info->digest_size);
	vcq_add_flush(&cmds[idx++], core_id);

	rctx->digest_buf = digest_buf;
	rctx->digest_dma = digest_dma;
	rctx->sgm = sgm;

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_HMAC_MAX_PACKED,
					    target_mbx,
					    cmh_hmac_complete, req,
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
	cmh_hmac_free_chunks(rctx, tctx);
	return ret;
}

static int cmh_hmac_finup(struct ahash_request *req)
{
	int ret;

	ret = cmh_hmac_update(req);
	if (ret)
		return ret;

	return cmh_hmac_final(req);
}

static int cmh_hmac_digest(struct ahash_request *req)
{
	int ret;

	ret = cmh_hmac_init(req);
	if (ret)
		return ret;

	return cmh_hmac_finup(req);
}

/*
 * ahash .export()/.import(): serialize/deserialize the software
 * accumulation buffer.  No HW state is involved.
 */

static int cmh_hmac_export(struct ahash_request *req, void *out)
{
	struct cmh_hmac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_hmac_export_state *state = out;
	struct cmh_hmac_chunk *chunk;
	u32 offset = 0;

	if (rctx->total_len > CMH_HMAC_EXPORT_MAX)
		return -ENOSPC;

	state->total_len = rctx->total_len;
	list_for_each_entry(chunk, &rctx->chunks, list) {
		memcpy(state->data + offset, chunk->data, chunk->len);
		offset += chunk->len;
	}
	return 0;
}

static int cmh_hmac_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_hmac_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_hmac_export_state *state = in;
	struct cmh_hmac_chunk *chunk;

	/*
	 * Do NOT call free_chunks() here: the crypto API does not
	 * guarantee the request context is in a valid state before
	 * import(), so the list pointers may be stale or invalid.
	 * Re-initialize from scratch instead.  Any pre-existing chunks
	 * are tracked on tctx->all_chunks and freed in cra_exit.
	 */
	rctx->info = cmh_hmac_get_info(tfm);
	rctx->error = 0;
	INIT_LIST_HEAD(&rctx->chunks);
	rctx->num_chunks = 0;
	rctx->total_len = 0;

	if (state->total_len > CMH_HMAC_EXPORT_MAX)
		return -EINVAL;

	if (state->total_len) {
		chunk = kmalloc(sizeof(*chunk) + state->total_len, GFP_KERNEL);
		if (!chunk)
			return -ENOMEM;
		chunk->len = state->total_len;
		memcpy(chunk->data, state->data, state->total_len);
		list_add_tail(&chunk->list, &rctx->chunks);
		spin_lock_bh(&tctx->chunk_lock);
		list_add_tail(&chunk->tfm_node, &tctx->all_chunks);
		spin_unlock_bh(&tctx->chunk_lock);
		rctx->num_chunks = 1;
		rctx->total_len = state->total_len;
	}
	return 0;
}

/* Transform init/exit (cra_init/cra_exit) */

static int cmh_hmac_cra_init(struct crypto_tfm *tfm)
{
	struct cmh_hmac_tfm_ctx *tctx = crypto_tfm_ctx(tfm);

	memset(tctx, 0, sizeof(*tctx));
	tctx->key.mode = CMH_KEY_NONE;
	spin_lock_init(&tctx->chunk_lock);
	INIT_LIST_HEAD(&tctx->all_chunks);
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct cmh_hmac_reqctx));
	return 0;
}

static void cmh_hmac_cra_exit(struct crypto_tfm *tfm)
{
	struct cmh_hmac_tfm_ctx *tctx = crypto_tfm_ctx(tfm);
	struct cmh_hmac_chunk *chunk, *tmp;

	/* Free any orphaned chunks (e.g. testmgr export/reimport poison) */
	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(chunk, tmp, &tctx->all_chunks, tfm_node) {
		list_del(&chunk->tfm_node);
		kfree_sensitive(chunk);
	}
	spin_unlock_bh(&tctx->chunk_lock);

	cmh_key_destroy(&tctx->key);
}

/* Registration */

static struct cmh_hmac_alg_drv cmh_hmac_drvs[CMH_HMAC_ALG_COUNT];

/**
 * cmh_hmac_register() - Register HMAC-SHA hash algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_hmac_register(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < CMH_HMAC_ALG_COUNT; i++) {
		const struct cmh_hmac_alg_info *info = &cmh_hmac_algs_info[i];
		struct cmh_hmac_alg_drv *drv = &cmh_hmac_drvs[i];
		struct ahash_alg *alg = &drv->alg;

		drv->info = info;

		alg->init   = cmh_hmac_init;
		alg->update = cmh_hmac_update;
		alg->final  = cmh_hmac_final;
		alg->finup  = cmh_hmac_finup;
		alg->digest = cmh_hmac_digest;
		alg->export = cmh_hmac_export;
		alg->import = cmh_hmac_import;
		alg->setkey = cmh_hmac_setkey;

		alg->halg.digestsize = info->digest_size;
		alg->halg.statesize  = CMH_HMAC_STATE_SIZE;

		strscpy(alg->halg.base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->halg.base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->halg.base.cra_priority    = 300;
		alg->halg.base.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
						 CRYPTO_ALG_NO_FALLBACK |
						 CRYPTO_ALG_ASYNC |
						 CRYPTO_ALG_REQ_VIRT;
		alg->halg.base.cra_blocksize   = info->block_size;
		alg->halg.base.cra_ctxsize     = sizeof(struct cmh_hmac_tfm_ctx);
		alg->halg.base.cra_init        = cmh_hmac_cra_init;
		alg->halg.base.cra_exit        = cmh_hmac_cra_exit;
		alg->halg.base.cra_module      = THIS_MODULE;

		ret = crypto_register_ahash(alg);
		if (ret) {
			dev_err(cmh_dev(), "hmac: failed to register %s (rc=%d)\n",
				info->drv_name, ret);
			while (i--)
				crypto_unregister_ahash(&cmh_hmac_drvs[i].alg);
			return ret;
		}

		dev_dbg(cmh_dev(), "hmac: registered %s (priority 300)\n",
			info->drv_name);
	}

	dev_info(cmh_dev(), "hmac: %zu algorithm(s) registered\n",
		 CMH_HMAC_ALG_COUNT);
	return 0;
}

/**
 * cmh_hmac_unregister() - Unregister HMAC-SHA hash algorithms from the crypto framework
 */
void cmh_hmac_unregister(void)
{
	unsigned int i;

	for (i = 0; i < CMH_HMAC_ALG_COUNT; i++) {
		crypto_unregister_ahash(&cmh_hmac_drvs[i].alg);
		dev_dbg(cmh_dev(), "hmac: unregistered %s\n",
			cmh_hmac_algs_info[i].drv_name);
	}

	dev_info(cmh_dev(), "hmac: cleaned up\n");
}
