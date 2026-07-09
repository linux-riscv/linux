// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API AES-CMAC (ahash) Driver
 *
 * Registers cmac(aes) as an ahash algorithm.
 *
 * CMAC produces a 16-byte tag (MAC) from a key and message.
 * VCQ sequence: [SYS_CMD_WRITE] + AES_CMD_INIT(CMAC) +
 *               AES_CMD_AAD_FINAL_AUTH + FLUSH
 *
 * The ahash interface accumulates data in a kernel buffer via .update(),
 * then .final() builds and submits the VCQ asynchronously.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_aes.h"
#include "cmh_vcq.h"
#include "cmh_aes_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

#define AES_CMAC_DIGEST_SIZE	16U
#define AES_CMAC_BLOCK_SIZE	16U

/*
 * Maximum accumulated data for CMAC -- driver-imposed, not HW.
 *
 * The AES core does not expose external save/restore VCQ commands,
 * so the driver must accumulate all data in kernel memory via
 * .update() and submit it atomically in .final().  This cap limits
 * the per-request kernel allocation.
 */
#define AES_CMAC_MAX_DATA	(64 * 1024)

/* Per-transform context */
struct cmh_aes_cmac_tfm_ctx {
	struct cmh_key_ctx key;
	spinlock_t         chunk_lock;  /* protects all_chunks */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
};

/* One chunk per .update() call -- data is embedded via flexible array */
struct cmh_aes_cmac_chunk {
	struct list_head list;
	struct list_head tfm_node; /* per-tfm orphan tracking */
	u32 len;
	u8 data[];
};

/* Per-request context (lives in ahash_request::__ctx) */

/*
 * Maximum payload commands:
 *   [SYS_CMD_WRITE] + AES_CMD_INIT + AES_CMD_AAD_FINAL_AUTH + FLUSH = 4
 */
#define CMH_AES_CMAC_MAX_PAYLOAD	4
#define CMH_AES_CMAC_MAX_PACKED		(CMH_AES_CMAC_MAX_PAYLOAD * 2)

struct cmh_aes_cmac_reqctx {
	struct list_head chunks;
	u32  total_len;
	u8  *buf;	/* linearised in final() for DMA */
	/* DMA state for async final */
	dma_addr_t key_dma;
	dma_addr_t in_dma;
	dma_addr_t tag_dma;
	u8 *tag_buf;
	u32 keylen;
	struct vcq_cmd packed[CMH_AES_CMAC_MAX_PACKED];
};

/* Flat state for export/import -- holds accumulated input data only */
struct cmh_aes_cmac_export_state {
	u32 total_len;
	u8  data[];
};

/*
 * Flat state buffer for export/import.  The CMH AES core does not
 * support save/restore of intermediate CMAC state, so this driver
 * accumulates input in SW and serialises the buffer on export.
 *
 * PAGE_SIZE (4096) caps the exportable accumulated-data window.
 * Full-range export is not feasible because the crypto subsystem
 * pre-allocates statesize bytes per request.  Export returns -EINVAL
 * if the caller has accumulated more than CMH_AES_CMAC_EXPORT_MAX.
 */
#define CMH_AES_CMAC_STATE_SIZE 4096
#define CMH_AES_CMAC_EXPORT_MAX \
	(CMH_AES_CMAC_STATE_SIZE - sizeof(struct cmh_aes_cmac_export_state))

/*
 * Export/import: not supported.
 *
 * The AES core lacks external save/restore VCQ commands, so there is
 * no way to checkpoint intermediate CMAC state to host memory.
 * Pending eSW ABI extension to add save/restore for the AES core.
 */

static int cmh_aes_cmac_setkey(struct crypto_ahash *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);

	if (keylen != 16 && keylen != 24 && keylen != 32)
		return -EINVAL;

	return cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_AES);
}

static void cmh_aes_cmac_free_chunks(struct cmh_aes_cmac_reqctx *rctx,
				     struct cmh_aes_cmac_tfm_ctx *tctx)
{
	struct cmh_aes_cmac_chunk *c, *tmp;

	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(c, tmp, &rctx->chunks, list) {
		list_del(&c->list);
		list_del(&c->tfm_node);
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);
	rctx->total_len = 0;
}

static int cmh_aes_cmac_init(struct ahash_request *req)
{
	struct cmh_aes_cmac_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(*rctx));
	INIT_LIST_HEAD(&rctx->chunks);
	return 0;
}

static int cmh_aes_cmac_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_aes_cmac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_aes_cmac_chunk *chunk;
	gfp_t gfp;
	int ret;

	if (!req->nbytes)
		return 0;

	if (req->nbytes > AES_CMAC_MAX_DATA - rctx->total_len) {
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
	 * callers may not call .final() on error, so they would leak.
	 */
	cmh_aes_cmac_free_chunks(rctx, tctx);
	return ret;
}

static void cmh_aes_cmac_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_aes_cmac_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	/* Unmap DMA */
	if (rctx->total_len > 0)
		cmh_dma_unmap_single(rctx->in_dma, rctx->total_len,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->tag_dma, AES_CMAC_DIGEST_SIZE,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->tag_buf, AES_CMAC_DIGEST_SIZE);

	kfree(rctx->tag_buf);
	rctx->tag_buf = NULL;
	kfree_sensitive(rctx->buf);
	rctx->buf = NULL;
	cmh_aes_cmac_free_chunks(rctx, tctx);
	cmh_complete(&req->base, error);
}

static int cmh_aes_cmac_final(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_aes_cmac_reqctx *rctx = ahash_request_ctx(req);
	struct vcq_cmd cmds[CMH_AES_CMAC_MAX_PAYLOAD];
	u64 key_ref;
	u32 keylen;
	struct core_dispatch d;
	s32 target_mbx;
	u32 core_id;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (tctx->key.mode == CMH_KEY_NONE) {
		ret = -ENOKEY;
		goto out_free_buf;
	}

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/* Linearise accumulated chunks into a contiguous buffer for DMA */
	if (rctx->total_len > 0) {
		struct cmh_aes_cmac_chunk *c;
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
	rctx->tag_buf = kzalloc(AES_CMAC_DIGEST_SIZE, gfp);
	if (!rctx->tag_buf) {
		ret = -ENOMEM;
		goto out_free_buf;
	}

	rctx->tag_dma = cmh_dma_map_single(rctx->tag_buf,
					   AES_CMAC_DIGEST_SIZE,
					    DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->tag_dma)) {
		ret = -ENOMEM;
		goto out_free_tag;
	}

	/* Map input data (may be zero-length for empty CMAC) */
	if (rctx->total_len > 0) {
		rctx->in_dma = cmh_dma_map_single(rctx->buf, rctx->total_len,
						  DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->in_dma)) {
			ret = -ENOMEM;
			goto out_unmap_tag;
		}
	}

	/* Resolve key */
	idx = 0;

	rctx->key_dma = tctx->key.raw.dma;
	rctx->keylen = tctx->key.raw.len;
	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP,
			  (u64)rctx->key_dma, SYS_REF_NONE,
			  tctx->key.raw.len,
			  tctx->key.raw.sys_type);
	key_ref = SYS_REF_TEMP;
	keylen = tctx->key.raw.len;
	d = cmh_core_select_instance(CMH_CORE_AES);
	target_mbx = d.mbx_idx;
	core_id = d.core_id;

	/*
	 * INIT: mode=CMAC, op=ENCRYPT (CMAC always "encrypts")
	 * CMAC data goes through the AAD path:
	 *   aadlen = total data length, iolen = 0
	 */
	{
		struct vcq_cmd *slot = &cmds[idx++];

		memset(slot, 0, sizeof(*slot));
		slot->magic = VCQ_CMD_MAGIC;
		slot->id = VCQ_CMD_ID(core_id, 0, 1, AES_CMD_INIT);
		slot->hwc.aes.cmd_init.key = key_ref;
		slot->hwc.aes.cmd_init.iv = 0;
		slot->hwc.aes.cmd_init.keylen = keylen;
		slot->hwc.aes.cmd_init.ivlen = 0;
		slot->hwc.aes.cmd_init.mode = AES_MODE_CMAC;
		slot->hwc.aes.cmd_init.op = AES_OP_ENCRYPT;
		slot->hwc.aes.cmd_init.aadlen = rctx->total_len;
		slot->hwc.aes.cmd_init.iolen = 0;
		slot->hwc.aes.cmd_init.taglen = AES_CMAC_DIGEST_SIZE;
	}

	/* AAD_FINAL_AUTH: final AAD + tag extraction in one atomic step */
	{
		struct vcq_cmd *slot = &cmds[idx++];

		memset(slot, 0, sizeof(*slot));
		slot->magic = VCQ_CMD_MAGIC;
		slot->id = VCQ_CMD_ID(core_id, 0, 1, AES_CMD_AAD_FINAL_AUTH);
		slot->hwc.aes.cmd_aad_final_auth.data =
			rctx->total_len > 0 ? (u64)rctx->in_dma : 0;
		slot->hwc.aes.cmd_aad_final_auth.datalen = rctx->total_len;
		slot->hwc.aes.cmd_aad_final_auth.tag = (u64)rctx->tag_dma;
		slot->hwc.aes.cmd_aad_final_auth.taglen = AES_CMAC_DIGEST_SIZE;
	}

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_AES_CMAC_MAX_PACKED,
					    target_mbx,
					    cmh_aes_cmac_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	/* -EBUSY = backlogged; ownership transferred to callback. */
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_cleanup_all;

	return -EINPROGRESS;

out_cleanup_all:
	if (rctx->total_len > 0 && !cmh_dma_map_error(rctx->in_dma))
		cmh_dma_unmap_single(rctx->in_dma, rctx->total_len,
				     DMA_TO_DEVICE);
out_unmap_tag:
	cmh_dma_unmap_single(rctx->tag_dma, AES_CMAC_DIGEST_SIZE,
			     DMA_FROM_DEVICE);
out_free_tag:
	kfree(rctx->tag_buf);
out_free_buf:
out_free_chunks:
	cmh_aes_cmac_free_chunks(rctx, tctx);
	kfree_sensitive(rctx->buf);
	rctx->buf = NULL;
	rctx->total_len = 0;
	return ret;
}

/*
 * ahash .export()/.import(): serialize/deserialize the software
 * accumulation buffer.  No HW state is involved -- the AES core
 * does not support save/restore, but we only export the input queue.
 */

static int cmh_aes_cmac_export(struct ahash_request *req, void *out)
{
	struct cmh_aes_cmac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_aes_cmac_export_state *state = out;
	struct cmh_aes_cmac_chunk *chunk;
	u32 offset = 0;

	if (rctx->total_len > CMH_AES_CMAC_EXPORT_MAX)
		return -ENOSPC;

	state->total_len = rctx->total_len;
	list_for_each_entry(chunk, &rctx->chunks, list) {
		memcpy(state->data + offset, chunk->data, chunk->len);
		offset += chunk->len;
	}
	return 0;
}

static int cmh_aes_cmac_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_aes_cmac_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_aes_cmac_export_state *state = in;
	struct cmh_aes_cmac_chunk *chunk;

	/*
	 * Do NOT call free_chunks() here: the crypto API does not
	 * guarantee the request context is in a valid state before
	 * import(), so the list pointers may be stale or invalid.
	 * Re-initialize from scratch instead.  Any pre-existing chunks
	 * are tracked on tctx->all_chunks and freed in exit_tfm.
	 */
	memset(rctx, 0, sizeof(*rctx));
	INIT_LIST_HEAD(&rctx->chunks);

	if (state->total_len > CMH_AES_CMAC_EXPORT_MAX)
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
		rctx->total_len = state->total_len;
	}
	return 0;
}

static int cmh_aes_cmac_finup(struct ahash_request *req)
{
	int err;

	err = cmh_aes_cmac_update(req);
	if (err)
		return err;
	return cmh_aes_cmac_final(req);
}

static int cmh_aes_cmac_digest(struct ahash_request *req)
{
	int err;

	err = cmh_aes_cmac_init(req);
	if (err)
		return err;
	return cmh_aes_cmac_finup(req);
}

static int cmh_aes_cmac_init_tfm(struct crypto_ahash *tfm)
{
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);

	memset(tctx, 0, sizeof(*tctx));
	spin_lock_init(&tctx->chunk_lock);
	INIT_LIST_HEAD(&tctx->all_chunks);
	crypto_ahash_set_reqsize(tfm, sizeof(struct cmh_aes_cmac_reqctx));
	return 0;
}

static void cmh_aes_cmac_exit_tfm(struct crypto_ahash *tfm)
{
	struct cmh_aes_cmac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_aes_cmac_chunk *c, *tmp;

	/* Free any orphaned chunks (e.g. testmgr export/reimport poison) */
	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(c, tmp, &tctx->all_chunks, tfm_node) {
		list_del(&c->tfm_node);
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);

	cmh_key_destroy(&tctx->key);
}

static struct ahash_alg cmh_aes_cmac_alg = {
	.init		= cmh_aes_cmac_init,
	.update		= cmh_aes_cmac_update,
	.final		= cmh_aes_cmac_final,
	.finup		= cmh_aes_cmac_finup,
	.digest		= cmh_aes_cmac_digest,
	.export		= cmh_aes_cmac_export,
	.import		= cmh_aes_cmac_import,
	.setkey		= cmh_aes_cmac_setkey,
	.init_tfm	= cmh_aes_cmac_init_tfm,
	.exit_tfm	= cmh_aes_cmac_exit_tfm,
	.halg		= {
		.digestsize	= AES_CMAC_DIGEST_SIZE,
		.statesize	= CMH_AES_CMAC_STATE_SIZE,
		.base		= {
			.cra_name	 = "cmac(aes)",
			.cra_driver_name = "cri-cmh-cmac-aes",
			.cra_priority	 = 300,
			.cra_flags	 = CRYPTO_ALG_KERN_DRIVER_ONLY |
					   CRYPTO_ALG_NO_FALLBACK |
					   CRYPTO_ALG_ASYNC |
					   CRYPTO_ALG_REQ_VIRT,
			.cra_blocksize	 = AES_CMAC_BLOCK_SIZE,
			.cra_ctxsize	 = sizeof(struct cmh_aes_cmac_tfm_ctx),
			.cra_module	 = THIS_MODULE,
		},
	},
};

/**
 * cmh_aes_cmac_register() - Register AES-CMAC hash algorithm with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_aes_cmac_register(void)
{
	int ret;

	ret = crypto_register_ahash(&cmh_aes_cmac_alg);
	if (ret)
		dev_err(cmh_dev(), "cmh_aes_cmac: failed to register cmac(aes) (rc=%d)\n",
			ret);
	else
		dev_dbg(cmh_dev(), "cmh_aes_cmac: registered cmac(aes)\n");

	return ret;
}

/**
 * cmh_aes_cmac_unregister() - Unregister AES-CMAC hash algorithm from the crypto framework
 */
void cmh_aes_cmac_unregister(void)
{
	crypto_unregister_ahash(&cmh_aes_cmac_alg);
	dev_dbg(cmh_dev(), "cmh_aes_cmac: unregistered cmac(aes)\n");
}
