// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API Hash Driver
 *
 * Registers asynchronous hash (ahash) algorithms with the Linux crypto
 * subsystem.  Implements SHA-2 (224/256/384/512), SHA-3
 * (224/256/384/512), and SHAKE (128/256) families using the CMH Hash
 * Core (HC).
 *
 * Incremental HW update model.  The driver sets
 * CRYPTO_AHASH_ALG_BLOCK_ONLY, so the Crypto API buffers partial
 * blocks: .update() is only handed whole-block-aligned data and returns
 * any sub-block remainder for the API to hold until the next call.
 *
 *   .init()   -> software-only: zero per-request context
 *   .update() -> INIT [+ RESTORE] + UPDATE(full blocks) + SAVE + FLUSH;
 *                return -EINPROGRESS, completing with the leftover byte
 *                count the API must buffer (0 when block-aligned)
 *   .finup()  -> INIT [+ RESTORE] [+ UPDATE(residual)] + FINAL + FLUSH
 *                (also serves .final via the API: nbytes == 0)
 *   .digest() -> INIT + UPDATE + FINAL + FLUSH (single-shot via finup)
 *   .export()/.import() -> software-only: copy the HC context
 *                checkpoint; the API appends its own partial-block buffer
 *
 * The FLUSH after each .update() releases the HC core, so no lockout.
 * Two hash sessions interleave fine on the same MBX -- each saves its
 * own state via SAVE and restores via RESTORE on the next call.
 *
 * These are sg-only drivers (no CRYPTO_ALG_REQ_VIRT): BLOCK_ONLY buffer
 * prepending assumes scatterlists.  Export/import carry only HW state,
 * enabling crypto API transform clone for all plain-hash algorithms.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_hash.h"
#include "cmh_vcq.h"
#include "cmh_txn.h"
#include "cmh_dma.h"

/* Algorithm Table */

struct cmh_hash_alg_info {
	u32         hc_algo;        /* HC_ALGO_* (SHA2, SHA3, SHAKE) */
	u32         digest_size;    /* bytes */
	u32         block_size;     /* cra_blocksize for Linux crypto API */
	const char *alg_name;       /* Linux crypto name: "sha256" */
	const char *drv_name;       /* driver name: "rambus-cmh-sha256" */
};

static const struct cmh_hash_alg_info cmh_hash_algs_info[] = {
	/* SHA-2 family */
	{
		.hc_algo     = HC_ALGO_SHA2_224,
		.digest_size = CMH_SHA224_DIGEST_SIZE,
		.block_size  = 64,
		.alg_name    = "sha224",
		.drv_name    = "rambus-cmh-sha224",
	},
	{
		.hc_algo     = HC_ALGO_SHA2_256,
		.digest_size = CMH_SHA256_DIGEST_SIZE,
		.block_size  = 64,
		.alg_name    = "sha256",
		.drv_name    = "rambus-cmh-sha256",
	},
	{
		.hc_algo     = HC_ALGO_SHA2_384,
		.digest_size = CMH_SHA384_DIGEST_SIZE,
		.block_size  = 128,
		.alg_name    = "sha384",
		.drv_name    = "rambus-cmh-sha384",
	},
	{
		.hc_algo     = HC_ALGO_SHA2_512,
		.digest_size = CMH_SHA512_DIGEST_SIZE,
		.block_size  = 128,
		.alg_name    = "sha512",
		.drv_name    = "rambus-cmh-sha512",
	},
	/* SHA-3 family */
	{
		.hc_algo     = HC_ALGO_SHA3_224,
		.digest_size = CMH_SHA3_224_DIGEST_SIZE,
		.block_size  = 144,  /* rate = 1600/8 - 2*224/8 = 144 */
		.alg_name    = "sha3-224",
		.drv_name    = "rambus-cmh-sha3-224",
	},
	{
		.hc_algo     = HC_ALGO_SHA3_256,
		.digest_size = CMH_SHA3_256_DIGEST_SIZE,
		.block_size  = 136,  /* rate = 1600/8 - 2*256/8 = 136 */
		.alg_name    = "sha3-256",
		.drv_name    = "rambus-cmh-sha3-256",
	},
	{
		.hc_algo     = HC_ALGO_SHA3_384,
		.digest_size = CMH_SHA3_384_DIGEST_SIZE,
		.block_size  = 104,  /* rate = 1600/8 - 2*384/8 = 104 */
		.alg_name    = "sha3-384",
		.drv_name    = "rambus-cmh-sha3-384",
	},
	{
		.hc_algo     = HC_ALGO_SHA3_512,
		.digest_size = CMH_SHA3_512_DIGEST_SIZE,
		.block_size  = 72,   /* rate = 1600/8 - 2*512/8 = 72 */
		.alg_name    = "sha3-512",
		.drv_name    = "rambus-cmh-sha3-512",
	},
	/*
	 * SHAKE (XOF) family -- fixed-output ahash registration.
	 *
	 * cra_blocksize = 1: SHAKE is a sponge/XOF, not Merkle-Damgaard.
	 * With BLOCK_ONLY this means the API never holds anything back and
	 * every byte reaches .update(); the HC core absorbs any sub-rate
	 * remainder into its saved context across SAVE/RESTORE, so unaligned
	 * intermediate absorbs are fine.
	 */
	{
		.hc_algo     = HC_ALGO_SHAKE128,
		.digest_size = CMH_SHAKE128_DIGEST_SIZE,
		.block_size  = 1,    /* XOF: no meaningful block for crypto API */
		.alg_name    = "shake128",
		.drv_name    = "rambus-cmh-shake128",
	},
	{
		.hc_algo     = HC_ALGO_SHAKE256,
		.digest_size = CMH_SHAKE256_DIGEST_SIZE,
		.block_size  = 1,    /* XOF: no meaningful block for crypto API */
		.alg_name    = "shake256",
		.drv_name    = "rambus-cmh-shake256",
	},
};

#define CMH_HASH_ALG_COUNT  ARRAY_SIZE(cmh_hash_algs_info)

/* Per-Request State */

/*
 * Exported hash state -- serialised by .export(), deserialised by
 * .import().  This is what statesize advertises to the crypto
 * subsystem; the API appends its own partial-block buffer on top.
 */
struct cmh_hash_export_state {
	u8  checkpoint[HC_CONTEXT_SIZE]; /* HC context from last SAVE */
	u32 hw_started;                  /* non-zero if checkpoint valid */
};

/*
 * Maximum payload commands any hash transaction can produce:
 *   INIT + RESTORE + UPDATE + SAVE/FINAL + FLUSH = 5
 * Worst-case packed output (stride=7, 1 payload per VCQ):
 *   5 VCQs x 2 entries = 10
 */
#define CMH_HASH_MAX_PAYLOAD    5
#define CMH_HASH_MAX_PACKED     (CMH_HASH_MAX_PAYLOAD * 2)

/*
 * Stored in ahash_request_ctx().  Tracks the algorithm, an HC context
 * checkpoint from the last SAVE, and DMA state for the current in-flight
 * async operation.  Partial-block buffering is handled by the Crypto API
 * (CRYPTO_AHASH_ALG_BLOCK_ONLY), not here.
 *
 * The checkpoint is embedded inline rather than heap-allocated because
 * the kernel ahash API has no per-request destructor.  If a request is
 * abandoned without a final op (e.g. transform freed early), a heap
 * checkpoint would leak unconditionally.
 *
 * Mapping the inline checkpoint for DMA is safe even on non-coherent
 * platforms: it is only ever mapped DMA_TO_DEVICE, and its bytes are
 * frozen from dma_map_single() until the matching unmap (it is written
 * solely in the completion, after the unmap).  The device therefore
 * always reads the value written back at map time, regardless of CPU
 * writes to adjacent fields (packed[]) sharing the same cacheline --
 * those writes never alter the checkpoint bytes, and a TO_DEVICE unmap
 * performs no cache invalidate.  The shared-cacheline hazard applies
 * only to FROM_DEVICE / BIDIRECTIONAL mappings, and all such buffers
 * here (save_buf, digest_buf) are separately kmalloc'd.
 */
struct cmh_hash_reqctx {
	const struct cmh_hash_alg_info *info;
	int    error;
	u32    hw_started;      /* non-zero after first HW submission */
	u32    has_checkpoint;  /* non-zero if checkpoint[] valid */
	u32    update_remainder; /* sub-block bytes the API must re-buffer */
	/* DMA state for current async operation */
	dma_addr_t ckpt_dma;   /* RESTORE input */
	dma_addr_t save_dma;   /* SAVE output (update only) */
	dma_addr_t data_dma;   /* UPDATE input */
	dma_addr_t digest_dma; /* FINAL output (final/digest only) */
	u8    *save_buf;       /* SAVE output buffer */
	u8    *data_buf;       /* linearised data for DMA */
	u32    data_len;       /* bytes in data_buf */
	u8    *digest_buf;     /* digest output buffer */
	u8     checkpoint[HC_CONTEXT_SIZE]; /* HC context from last SAVE */
	struct vcq_cmd packed[CMH_HASH_MAX_PACKED];
};

/* VCQ Builders (HC-specific; shared builders in cmh_hc_abi.h / cmh_vcq.h) */

/* Add an HC_CMD_UPDATE entry */
static void vcq_add_hc_update(struct vcq_cmd *slot, u32 core_id, u64 input_phys, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_UPDATE);
	slot->hwc.hc.cmd_update.input = input_phys;
	slot->hwc.hc.cmd_update.inlen = len;
}

/* Add an HC_CMD_SAVE entry */
static void vcq_add_hc_save(struct vcq_cmd *slot, u32 core_id, u64 output_phys, u32 outlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_SAVE);
	slot->hwc.hc.cmd_save.output = output_phys;
	slot->hwc.hc.cmd_save.outlen = outlen;
}

/* Add an HC_CMD_RESTORE entry */
static void vcq_add_hc_restore(struct vcq_cmd *slot, u32 core_id, u64 input_phys, u32 inlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_RESTORE);
	slot->hwc.hc.cmd_restore.input = input_phys;
	slot->hwc.hc.cmd_restore.inlen = inlen;
}

/* Request Context Cleanup */

static void cmh_hash_free_reqctx(struct cmh_hash_reqctx *rctx)
{
	rctx->has_checkpoint = 0;
}

/* VCQ Packing + Submit */

/* ahash Operations */

/*
 * Wrapper struct: embeds ahash_alg + a pointer to our alg_info table
 * entry so we can recover it in the tfm callbacks.
 */
struct cmh_hash_alg_drv {
	struct ahash_alg                 alg;
	const struct cmh_hash_alg_info  *info;
};

/*
 * Find the cmh_hash_alg_info from the crypto_ahash (embedded in our
 * registered template).  We stash the info pointer in the algorithm's
 * driver-private area at registration time (see cmh_hash_register).
 */
static const struct cmh_hash_alg_info *
cmh_hash_get_info(struct crypto_ahash *tfm)
{
	struct ahash_alg *alg = crypto_ahash_alg(tfm);

	return container_of(alg, struct cmh_hash_alg_drv, alg)->info;
}

static int cmh_hash_init(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(*rctx));
	rctx->info = cmh_hash_get_info(tfm);
	return 0;
}

/*
 * Update completion -- called from threaded IRQ after SAVE completes.
 * Takes ownership of save_buf as the new checkpoint.
 */
static void cmh_hash_update_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	/* Unmap DMA buffers */
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

/*
 * .update -- submit whole blocks to HW.
 *
 * With CRYPTO_AHASH_ALG_BLOCK_ONLY the Crypto API prepends any bytes it
 * held back from earlier calls, so req->src carries at least one full
 * block.  We hash the block-aligned prefix as:
 *   INIT [+ RESTORE] + UPDATE(full blocks) + SAVE + FLUSH
 * and return the sub-block remainder for the API to re-buffer (reported
 * through the async completion).  For XOFs (block_size 1) there is never
 * a remainder; the HC core absorbs sub-rate data across SAVE/RESTORE.
 */
static int cmh_hash_update(struct ahash_request *req)
{
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_hash_alg_info *info = rctx->info;
	struct vcq_cmd cmds[CMH_HASH_MAX_PAYLOAD];
	struct core_dispatch d;
	u32 block_size = info->block_size;
	u32 full_len;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (rctx->error)
		return rctx->error;

	if (!req->nbytes)
		return 0;

	/*
	 * block_size is not always a power of two (SHA-3 rates: 144/136/
	 * 104/72), so use modulo -- round_down() would corrupt the split.
	 */
	rctx->update_remainder = req->nbytes % block_size;
	full_len = req->nbytes - rctx->update_remainder;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/*
	 * Reject a single update whose linearisation would exceed the largest
	 * kmalloc: return a permanent -EMSGSIZE ("message too long") rather
	 * than a transient -ENOMEM the client would keep retrying.
	 */
	if (full_len > KMALLOC_MAX_SIZE)
		return -EMSGSIZE;

	/*
	 * Linearise the block-aligned prefix from the scatterlist.
	 * __GFP_NOWARN keeps a borderline-large (but sub-cap) request from
	 * splatting the page allocator if it still cannot be satisfied.
	 */
	rctx->data_buf = kmalloc(full_len, gfp | __GFP_NOWARN);
	if (!rctx->data_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(rctx->data_buf, req->src, 0, full_len, 0);

	/* Allocate SAVE output buffer */
	rctx->save_buf = kzalloc(HC_CONTEXT_SIZE, gfp);
	if (!rctx->save_buf) {
		ret = -ENOMEM;
		goto err_free;
	}

	/* DMA map data, save output, and checkpoint */
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

	/* Build VCQ: INIT [+ RESTORE] + UPDATE + SAVE + FLUSH */
	d = cmh_core_select_instance(CMH_CORE_HC);
	idx = 0;

	vcq_add_hc_init(&cmds[idx++], d.core_id, info->hc_algo);

	if (rctx->has_checkpoint)
		vcq_add_hc_restore(&cmds[idx++], d.core_id,
				   (u64)rctx->ckpt_dma, HC_CONTEXT_SIZE);

	vcq_add_hc_update(&cmds[idx++], d.core_id,
			  (u64)rctx->data_dma, full_len);

	vcq_add_hc_save(&cmds[idx++], d.core_id,
			(u64)rctx->save_dma, HC_CONTEXT_SIZE);

	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_HASH_MAX_PACKED,
					    d.mbx_idx,
					    cmh_hash_update_complete, req,
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
 * Final completion -- unmap all DMA, copy digest, signal done.
 */
static void cmh_hash_final_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);

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
	cmh_hash_free_reqctx(rctx);
	cmh_complete(&req->base, error);
}

/*
 * Submit the final VCQ transaction:
 *   INIT [+ RESTORE] [+ UPDATE(residual)] + FINAL + FLUSH
 *
 * @data_buf: linearised residual data, or NULL for empty-hash.
 *            Ownership transferred -- callback frees it.
 * @data_len: bytes in data_buf.
 */
static int cmh_hash_submit_final(struct ahash_request *req,
				 u8 *data_buf, u32 data_len)
{
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_hash_alg_info *info = rctx->info;
	struct vcq_cmd cmds[CMH_HASH_MAX_PAYLOAD];
	struct core_dispatch d;
	u32 idx;
	int ret;
	gfp_t gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
		   GFP_KERNEL : GFP_ATOMIC;

	rctx->data_buf = data_buf;
	rctx->data_len = data_len;

	/* Allocate digest output buffer */
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

	/* Map residual data for UPDATE */
	rctx->data_dma = DMA_MAPPING_ERROR;
	if (data_buf && data_len > 0) {
		rctx->data_dma = cmh_dma_map_single(data_buf, data_len,
						    DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->data_dma)) {
			ret = -ENOMEM;
			goto err_unmap_digest;
		}
	}

	/* Map checkpoint for RESTORE */
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

	/* Build VCQ: INIT [+ RESTORE] [+ UPDATE] + FINAL + FLUSH */
	d = cmh_core_select_instance(CMH_CORE_HC);
	idx = 0;

	vcq_add_hc_init(&cmds[idx++], d.core_id, info->hc_algo);

	if (rctx->has_checkpoint)
		vcq_add_hc_restore(&cmds[idx++], d.core_id,
				   (u64)rctx->ckpt_dma, HC_CONTEXT_SIZE);

	if (data_buf && data_len > 0)
		vcq_add_hc_update(&cmds[idx++], d.core_id,
				  (u64)rctx->data_dma, data_len);

	vcq_add_hc_final(&cmds[idx++], d.core_id,
			 (u64)rctx->digest_dma, info->digest_size);

	vcq_add_flush(&cmds[idx++], d.core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_HASH_MAX_PACKED,
					    d.mbx_idx,
					    cmh_hash_final_complete, req,
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

static int cmh_hash_finup(struct ahash_request *req);

/*
 * One-shot digest -- delegates to init + finup so that all data is
 * linearised and mapped through cmh_dma_map_single(), which is the
 * only DMA mapping path aware of all supported DMA backends.
 */
static int cmh_hash_digest(struct ahash_request *req)
{
	int ret;

	ret = cmh_hash_init(req);
	if (ret)
		return ret;
	return cmh_hash_finup(req);
}

/*
 * .finup -- hash any remaining data and finalise in one transaction.
 *
 * With BLOCK_ONLY the Crypto API prepends the bytes it held back, so
 * req->src already carries the full tail; linearise it and submit
 * INIT [+ RESTORE] [+ UPDATE(residual)] + FINAL + FLUSH.  This also
 * serves .final (the API calls finup with nbytes == 0) and avoids
 * ahash_def_finup(), which would clone via export/import.
 */
static int cmh_hash_finup(struct ahash_request *req)
{
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);
	u32 data_len = req->nbytes;
	u8 *data_buf = NULL;
	gfp_t gfp;

	if (rctx->error)
		return rctx->error;

	if (data_len == 0)
		return cmh_hash_submit_final(req, NULL, 0);

	/* Reject an oversized linearisation with a permanent -EMSGSIZE. */
	if (data_len > KMALLOC_MAX_SIZE)
		return -EMSGSIZE;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	data_buf = kmalloc(data_len, gfp | __GFP_NOWARN);
	if (!data_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(data_buf, req->src, 0, data_len, 0);

	return cmh_hash_submit_final(req, data_buf, data_len);
}

/*
 * Export core -- purely software.
 *
 * Serialise the HC checkpoint (if any).  The Crypto API appends its own
 * partial-block buffer to the exported state; this callback carries only
 * HW state.  No HW interaction needed because the incremental model
 * keeps the checkpoint up-to-date after each .update().
 */
static int cmh_hash_export(struct ahash_request *req, void *out)
{
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_hash_export_state *state = out;

	/*
	 * Zero the whole exported state first: the struct may carry padding,
	 * so without this the padding would leak kernel memory to user space
	 * through the ahash export (e.g. algif_hash).
	 */
	memset(state, 0, sizeof(*state));

	if (rctx->hw_started && rctx->has_checkpoint)
		memcpy(state->checkpoint, rctx->checkpoint, HC_CONTEXT_SIZE);

	state->hw_started = rctx->hw_started;

	return 0;
}

/*
 * Import core -- purely software.
 *
 * Restore the HC checkpoint from a previously exported state.  The
 * Crypto API restores its own partial-block buffer separately.  The
 * next .update() or final op will RESTORE the checkpoint into HW.
 */
static int cmh_hash_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_hash_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_hash_export_state *state = in;

	memset(rctx, 0, sizeof(*rctx));
	rctx->info = cmh_hash_get_info(tfm);

	rctx->hw_started = state->hw_started;

	if (state->hw_started) {
		memcpy(rctx->checkpoint, state->checkpoint, HC_CONTEXT_SIZE);
		rctx->has_checkpoint = 1;
	}

	return 0;
}

/* Registration */

static struct cmh_hash_alg_drv cmh_hash_drvs[CMH_HASH_ALG_COUNT];

/**
 * cmh_hash_register() - Register SHA-256/384/512/3-256/3-384/3-512 hash algorithms
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_hash_register(void)
{
	unsigned int i;
	int ret;

	if (!cmh_core_present(CMH_CORE_HC))
		return 0;

	for (i = 0; i < CMH_HASH_ALG_COUNT; i++) {
		const struct cmh_hash_alg_info *info = &cmh_hash_algs_info[i];
		struct cmh_hash_alg_drv *drv = &cmh_hash_drvs[i];
		struct ahash_alg *alg = &drv->alg;

		drv->info = info;

		alg->init   = cmh_hash_init;
		alg->update = cmh_hash_update;
		alg->finup  = cmh_hash_finup;
		alg->digest = cmh_hash_digest;
		alg->export = cmh_hash_export;
		alg->import = cmh_hash_import;

		alg->halg.digestsize = info->digest_size;
		alg->halg.statesize  = sizeof(struct cmh_hash_export_state);

		strscpy(alg->halg.base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->halg.base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->halg.base.cra_priority    = 300;
		alg->halg.base.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
						 CRYPTO_ALG_NO_FALLBACK |
						 CRYPTO_ALG_ASYNC |
						 CRYPTO_AHASH_ALG_BLOCK_ONLY;
		alg->halg.base.cra_blocksize   = info->block_size;
		alg->halg.base.cra_ctxsize     = 0;
		alg->halg.base.cra_reqsize     = sizeof(struct cmh_hash_reqctx);
		alg->halg.base.cra_module      = THIS_MODULE;

		ret = crypto_register_ahash(alg);
		if (ret) {
			dev_err(cmh_dev(), "hash: failed to register %s (rc=%d)\n",
				info->drv_name, ret);
			/* Unregister any already-registered algorithms */
			while (i--)
				crypto_unregister_ahash(&cmh_hash_drvs[i].alg);
			return ret;
		}

		dev_dbg(cmh_dev(), "hash: registered %s (priority 300)\n",
			info->drv_name);
	}

	return 0;
}

/**
 * cmh_hash_unregister() - Unregister SHA hash algorithms from the crypto framework
 */
void cmh_hash_unregister(void)
{
	unsigned int i;

	if (!cmh_core_present(CMH_CORE_HC))
		return;

	for (i = 0; i < CMH_HASH_ALG_COUNT; i++) {
		crypto_unregister_ahash(&cmh_hash_drvs[i].alg);
		dev_dbg(cmh_dev(), "hash: unregistered %s\n",
			cmh_hash_algs_info[i].drv_name);
	}
}
