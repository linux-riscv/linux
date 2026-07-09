// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API AES (skcipher) Driver
 *
 * Registers skcipher algorithms with the Linux crypto subsystem:
 *   ecb(aes), cbc(aes), ctr(aes), cfb(aes), xts(aes)
 *
 * Uses the CMH AES Core via VCQ commands:
 *   [SYS_CMD_WRITE] + AES_CMD_INIT + [AES_CMD_UPDATE] + AES_CMD_FINAL
 *   + VCQ_CMD_FLUSH
 *
 * The AES core requires bidirectional DMA -- both input and output
 * buffers are mapped and passed in a single AES_CMD_FINAL command.
 *
 * Raw-key atomicity: SYS_CMD_WRITE to SYS_REF_TEMP is packed into
 * the same VCQ as AES commands (see cmh_key.h for details).
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/skcipher.h>
#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/xts.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "cmh_aes.h"
#include "cmh_vcq.h"
#include "cmh_aes_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/* Algorithm Table */

struct cmh_aes_alg_info {
	u32         aes_mode;	/* AES_MODE_* */
	u32         ivsize;		/* bytes (0 for ECB) */
	u32         min_keysize;	/* minimum key bytes */
	u32         max_keysize;	/* maximum key bytes */
	const char *alg_name;	/* Linux crypto name: "ecb(aes)" */
	const char *drv_name;	/* driver name: "cri-cmh-ecb-aes" */
};

static const struct cmh_aes_alg_info aes_algs[] = {
	{ AES_MODE_ECB, 0,                AES_KEYSIZE_128, AES_KEYSIZE_256,
	  "ecb(aes)", "cri-cmh-ecb-aes" },
	{ AES_MODE_CBC, CMH_AES_IV_SIZE,  AES_KEYSIZE_128, AES_KEYSIZE_256,
	  "cbc(aes)", "cri-cmh-cbc-aes" },
	{ AES_MODE_CTR, CMH_AES_IV_SIZE,  AES_KEYSIZE_128, AES_KEYSIZE_256,
	  "ctr(aes)", "cri-cmh-ctr-aes" },
	{ AES_MODE_CFB, CMH_AES_IV_SIZE,  AES_KEYSIZE_128, AES_KEYSIZE_256,
	  "cfb(aes)", "cri-cmh-cfb-aes" },
	{ AES_MODE_XTS, CMH_AES_IV_SIZE,  2 * AES_KEYSIZE_128, 2 * AES_KEYSIZE_256,
	  "xts(aes)", "cri-cmh-xts-aes" },
};

/* Per-transform context (allocated by crypto framework) */

struct cmh_aes_tfm_ctx {
	struct cmh_key_ctx key;
};

/* Per-request context (lives in skcipher_request::__ctx) */

/*
 * Maximum payload commands:
 *   [SYS_CMD_WRITE] + AES_CMD_INIT + [AES_CMD_UPDATE] + AES_CMD_FINAL
 *   + VCQ_CMD_FLUSH = 5
 * UPDATE is used for XTS data > 2 blocks (see cmh_aes_crypt).
 */
#define CMH_AES_MAX_PAYLOAD	5
#define CMH_AES_MAX_PACKED	(CMH_AES_MAX_PAYLOAD * 2)

struct cmh_aes_reqctx {
	dma_addr_t in_dma;
	dma_addr_t out_dma;
	dma_addr_t iv_dma;
	dma_addr_t iv2_dma;
	dma_addr_t key_dma;
	u8 *in_buf;
	u8 *out_buf;
	u8 *iv_buf;
	u8 *iv2_buf;
	u32 cryptlen;
	u32 ivsize;
	u32 keylen;
	u32 aes_mode;
	u32 aes_op;
	/* CTR counter-wrap split state */
	u32 ctr_chunk1_len;
	u32 core_id;
	s32 target_mbx;
	u64 key_ref;
	struct vcq_cmd packed[CMH_AES_MAX_PACKED];
};

/* VCQ Builders -- AES-specific */

static void vcq_add_aes_init(struct vcq_cmd *slot, u32 core_id, u64 key_ref, u64 iv_dma,
			     u32 keylen, u32 ivlen, u32 mode, u32 op,
			     u32 iolen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, AES_CMD_INIT);
	slot->hwc.aes.cmd_init.key = key_ref;
	slot->hwc.aes.cmd_init.iv = iv_dma;
	slot->hwc.aes.cmd_init.keylen = keylen;
	slot->hwc.aes.cmd_init.ivlen = ivlen;
	slot->hwc.aes.cmd_init.mode = mode;
	slot->hwc.aes.cmd_init.op = op;
	slot->hwc.aes.cmd_init.aadlen = 0;
	slot->hwc.aes.cmd_init.iolen = iolen;
	slot->hwc.aes.cmd_init.taglen = 0;
}

static void vcq_add_aes_update(struct vcq_cmd *slot, u32 core_id, u64 input_dma,
			       u64 output_dma, u32 iolen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, AES_CMD_UPDATE);
	slot->hwc.aes.cmd_update.input = input_dma;
	slot->hwc.aes.cmd_update.output = output_dma;
	slot->hwc.aes.cmd_update.iolen = iolen;
}

static void vcq_add_aes_final(struct vcq_cmd *slot, u32 core_id, u64 input_dma,
			      u64 output_dma, u32 iolen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, AES_CMD_FINAL);
	slot->hwc.aes.cmd_final.input = input_dma;
	slot->hwc.aes.cmd_final.output = output_dma;
	slot->hwc.aes.cmd_final.iolen = iolen;
	slot->hwc.aes.cmd_final.tag = 0;
	slot->hwc.aes.cmd_final.taglen = 0;
}

/*
 * We wrap each skcipher_alg with its info pointer in a compound struct,
 * then use container_of() in cmh_aes_get_info() to recover it.
 * This is the same pattern used by hash, hmac, cshake, kmac.
 */
struct cmh_aes_alg_drv {
	struct skcipher_alg             alg;
	const struct cmh_aes_alg_info  *info;
};

static bool aes_is_stream_mode(u32 mode)
{
	return mode == AES_MODE_CTR || mode == AES_MODE_CFB;
}

/*
 * Update req->iv after a successful encrypt/decrypt.
 *
 * The Linux skcipher API contract requires that req->iv is updated to
 * reflect the state needed to continue processing in a chained call:
 *   CBC encrypt: IV <- last ciphertext block
 *   CBC decrypt: IV <- last ciphertext block of the *input*
 *   CTR:         IV <- counter incremented by ceil(cryptlen / blocksize)
 *   CFB:         IV <- last ciphertext block
 */
static void cmh_aes_update_iv(struct skcipher_request *req, u32 mode,
			      u32 op, const u8 *in_buf, const u8 *out_buf)
{
	u32 bs = CMH_AES_BLOCK_SIZE;
	u32 nblocks;

	switch (mode) {
	case AES_MODE_CBC:
		if (op == AES_OP_ENCRYPT)
			memcpy(req->iv, out_buf + req->cryptlen - bs, bs);
		else
			memcpy(req->iv, in_buf + req->cryptlen - bs, bs);
		break;
	case AES_MODE_CTR:
		/*
		 * Arithmetic big-endian 128-bit counter increment.
		 * Process from the least-significant byte (index 15)
		 * upward, carrying as needed.
		 */
		nblocks = DIV_ROUND_UP(req->cryptlen, bs);
		{
			u8 *iv = req->iv;
			int i;

			for (i = bs - 1; i >= 0 && nblocks; i--) {
				u32 sum = (u32)iv[i] + (nblocks & 0xff);

				iv[i] = (u8)sum;
				nblocks = (nblocks >> 8) + (sum >> 8);
			}
		}
		break;
	case AES_MODE_CFB:
		/*
		 * CFB-128 chains on the last ciphertext block.  On encrypt,
		 * that is out_buf; on decrypt, it is in_buf.
		 *
		 * For sub-block requests (cryptlen < 16), there is no
		 * complete ciphertext block to chain, so the IV is left
		 * unchanged -- CFB-128 has no defined chaining semantic
		 * for partial blocks (shift-register CFB-n is a different
		 * mode).  Without this guard the pointer arithmetic
		 * underflows and reads before the buffer.
		 */
		if (req->cryptlen >= bs) {
			if (op == AES_OP_ENCRYPT)
				memcpy(req->iv, out_buf + req->cryptlen - bs,
				       bs);
			else
				memcpy(req->iv, in_buf + req->cryptlen - bs,
				       bs);
		}
		break;
	default:
		break;
	}
}

/* skcipher Operations */

static const struct cmh_aes_alg_info *
cmh_aes_get_info(struct crypto_skcipher *tfm)
{
	struct skcipher_alg *alg = crypto_skcipher_alg(tfm);

	return container_of(alg, struct cmh_aes_alg_drv, alg)->info;
}

static int cmh_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
			  unsigned int keylen)
{
	struct cmh_aes_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	const struct cmh_aes_alg_info *info = cmh_aes_get_info(tfm);

	if (info->aes_mode == AES_MODE_XTS) {
		int err;

		/* XTS: double key (32, 48, or 64 bytes) */
		if (keylen != 2 * AES_KEYSIZE_128 &&
		    keylen != 2 * AES_KEYSIZE_192 &&
		    keylen != 2 * AES_KEYSIZE_256)
			return -EINVAL;
		err = xts_verify_key(tfm, key, keylen);
		if (err)
			return err;
	} else {
		/* Standard: 16, 24, or 32 bytes */
		if (keylen != AES_KEYSIZE_128 &&
		    keylen != AES_KEYSIZE_192 &&
		    keylen != AES_KEYSIZE_256)
			return -EINVAL;
	}

	return cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_AES);
}

static int cmh_aes_init_tfm(struct crypto_skcipher *tfm)
{
	struct cmh_aes_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);

	memset(tctx, 0, sizeof(*tctx));
	crypto_skcipher_set_reqsize(tfm, sizeof(struct cmh_aes_reqctx));
	return 0;
}

static void cmh_aes_exit_tfm(struct crypto_skcipher *tfm)
{
	struct cmh_aes_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);

	cmh_key_destroy(&tctx->key);
}

#define CMH_AES_MAX_CRYPTLEN	SZ_32M

/* DMA unmap helper */
static void cmh_aes_unmap_dma(struct cmh_aes_reqctx *rctx)
{
	if (rctx->iv2_buf)
		cmh_dma_unmap_single(rctx->iv2_dma, rctx->ivsize,
				     DMA_TO_DEVICE);
	if (rctx->ivsize > 0)
		cmh_dma_unmap_single(rctx->iv_dma, rctx->ivsize,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->out_dma, rctx->cryptlen, DMA_FROM_DEVICE);
	cmh_dma_unmap_single(rctx->in_dma, rctx->cryptlen, DMA_TO_DEVICE);
}

static void cmh_aes_free_bufs(struct cmh_aes_reqctx *rctx)
{
	kfree(rctx->iv2_buf);
	rctx->iv2_buf = NULL;
	kfree(rctx->iv_buf);
	rctx->iv_buf = NULL;
	kfree_sensitive(rctx->out_buf);
	rctx->out_buf = NULL;
	kfree_sensitive(rctx->in_buf);
	rctx->in_buf = NULL;
}

/*
 * Submit the second CTR chunk after the first completes.
 * Called from cmh_aes_complete when ctr_chunk1_len > 0.
 */
static void cmh_aes_complete(void *data, int error);

static int cmh_aes_ctr_submit_chunk2(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct cmh_aes_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct cmh_aes_reqctx *rctx = skcipher_request_ctx(req);
	struct vcq_cmd cmds[CMH_AES_MAX_PAYLOAD];
	u32 chunk1 = rctx->ctr_chunk1_len;
	u32 chunk2 = rctx->cryptlen - chunk1;
	u64 key_ref;
	u32 keylen;
	u32 idx = 0;

	/* Clear split flag so next completion is final */
	rctx->ctr_chunk1_len = 0;

	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP,
			  (u64)rctx->key_dma, SYS_REF_NONE,
			  tctx->key.raw.len,
			  tctx->key.raw.sys_type);
	key_ref = SYS_REF_TEMP;
	keylen = tctx->key.raw.len;

	vcq_add_aes_init(&cmds[idx++], rctx->core_id, key_ref,
			 (u64)rctx->iv2_dma, keylen, rctx->ivsize,
			 rctx->aes_mode, rctx->aes_op, 0);
	vcq_add_aes_final(&cmds[idx++], rctx->core_id,
			  (u64)(rctx->in_dma + chunk1),
			  (u64)(rctx->out_dma + chunk1), chunk2);
	vcq_add_flush(&cmds[idx++], rctx->core_id);

	return cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					     CMH_AES_MAX_PACKED,
					     rctx->target_mbx,
					     cmh_aes_complete, req,
					     !!(req->base.flags &
						CRYPTO_TFM_REQ_MAY_BACKLOG),
					     cmh_tm_async_timeout_jiffies());
}

/*
 * Async completion callback -- fires from RH threaded IRQ context.
 *
 * Unmaps DMA buffers, copies output to req->dst scatterlist,
 * updates the IV state, frees temporaries, and completes the request.
 *
 * For CTR counter-wrap splits, the first chunk completion chains
 * into a second VCQ submission rather than finalizing immediately.
 */
static void cmh_aes_complete(void *data, int error)
{
	struct skcipher_request *req = data;
	struct cmh_aes_reqctx *rctx = skcipher_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	/*
	 * CTR counter-wrap: first chunk completed, submit second.
	 * DMA mappings remain valid (they cover the full buffer).
	 *
	 * Recursion depth bounded: chunk2 clears ctr_chunk1_len before
	 * submission, so the second cmh_aes_complete invocation sees 0
	 * and finalizes (max depth = 2).
	 */
	if (rctx->ctr_chunk1_len && !error) {
		int ret;

		ret = cmh_aes_ctr_submit_chunk2(req);

		if (!ret || ret == -EBUSY)
			return;
		/* Submission failed; clean up below */
		error = ret;
	}

	cmh_aes_unmap_dma(rctx);

	if (!error) {
		scatterwalk_map_and_copy(rctx->out_buf, req->dst,
					 0, rctx->cryptlen, 1);
		cmh_aes_update_iv(req, rctx->aes_mode, rctx->aes_op,
				  rctx->in_buf, rctx->out_buf);
	}

	cmh_aes_free_bufs(rctx);
	cmh_complete(&req->base, error);
}

/*
 * Core encrypt/decrypt -- builds a VCQ transaction and submits async.
 *
 * Returns -EINPROGRESS on successful submission (completion callback
 * will fire later).  Returns 0 for trivial cases (zero-length).
 * Returns negative errno on pre-submission errors.
 */
static int cmh_aes_crypt(struct skcipher_request *req, u32 aes_op)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct cmh_aes_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	const struct cmh_aes_alg_info *info = cmh_aes_get_info(tfm);
	struct cmh_aes_reqctx *rctx = skcipher_request_ctx(req);
	struct vcq_cmd cmds[CMH_AES_MAX_PAYLOAD];
	u64 key_ref;
	u32 keylen;
	struct core_dispatch d;
	s32 target_mbx;
	u32 core_id;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (tctx->key.mode == CMH_KEY_NONE)
		return -ENOKEY;

	if (!req->cryptlen)
		return 0;

	if (req->cryptlen > CMH_AES_MAX_CRYPTLEN)
		return -EINVAL;

	switch (info->aes_mode) {
	case AES_MODE_CTR:
	case AES_MODE_CFB:
		break;
	case AES_MODE_XTS:
		if (req->cryptlen < CMH_AES_BLOCK_SIZE)
			return -EINVAL;
		break;
	default:
		if (req->cryptlen & (CMH_AES_BLOCK_SIZE - 1))
			return -EINVAL;
		break;
	}

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/* Initialise reqctx */
	memset(rctx, 0, sizeof(*rctx));
	rctx->cryptlen = req->cryptlen;
	rctx->ivsize = info->ivsize;
	rctx->aes_mode = info->aes_mode;
	rctx->aes_op = aes_op;
	rctx->iv2_buf = NULL;

	/* Linearise input from scatterlist */
	rctx->in_buf = kmalloc(req->cryptlen, gfp);
	if (!rctx->in_buf)
		return -ENOMEM;

	scatterwalk_map_and_copy(rctx->in_buf, req->src, 0, req->cryptlen, 0);

	rctx->in_dma = cmh_dma_map_single(rctx->in_buf, req->cryptlen,
					  DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->in_dma)) {
		ret = -ENOMEM;
		goto out_free_in;
	}

	/* Allocate and map output buffer */
	rctx->out_buf = kmalloc(req->cryptlen, gfp);
	if (!rctx->out_buf) {
		ret = -ENOMEM;
		goto out_unmap_in;
	}

	rctx->out_dma = cmh_dma_map_single(rctx->out_buf, req->cryptlen,
					   DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->out_dma)) {
		ret = -ENOMEM;
		goto out_free_out;
	}

	/* Map IV if required */
	if (info->ivsize > 0) {
		rctx->iv_buf = kmemdup(req->iv, info->ivsize, gfp);
		if (!rctx->iv_buf) {
			ret = -ENOMEM;
			goto out_unmap_out;
		}
		rctx->iv_dma = cmh_dma_map_single(rctx->iv_buf, info->ivsize,
						  DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->iv_dma)) {
			ret = -ENOMEM;
			goto out_free_iv;
		}
	}

	/* Resolve key reference */
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
	 * iolen in INIT: XTS needs total length upfront for tweak
	 * computation; all other modes use 0 (streaming).
	 */
	vcq_add_aes_init(&cmds[idx++], core_id, key_ref, (u64)rctx->iv_dma,
			 keylen, info->ivsize, info->aes_mode, aes_op,
			 info->aes_mode == AES_MODE_XTS ?
			 req->cryptlen : 0);

	if (info->aes_mode == AES_MODE_XTS &&
	    req->cryptlen > 2 * CMH_AES_BLOCK_SIZE) {
		u32 final_len, update_len;

		if (req->cryptlen & (CMH_AES_BLOCK_SIZE - 1))
			final_len = CMH_AES_BLOCK_SIZE +
				    (req->cryptlen & (CMH_AES_BLOCK_SIZE - 1));
		else
			final_len = 2 * CMH_AES_BLOCK_SIZE;

		update_len = req->cryptlen - final_len;

		vcq_add_aes_update(&cmds[idx++], core_id,
				   (u64)rctx->in_dma,
				   (u64)rctx->out_dma, update_len);
		vcq_add_aes_final(&cmds[idx++], core_id,
				  (u64)(rctx->in_dma + update_len),
				  (u64)(rctx->out_dma + update_len),
				  final_len);
	} else if (info->aes_mode == AES_MODE_CTR) {
		/*
		 * CTR counter-wrap workaround:
		 * The AES-SCA hardware uses a 64-bit block counter.
		 * If the lower 64 bits of the IV would wrap during
		 * this operation, split into two separate VCQ
		 * transactions -- the completion callback for the
		 * first chunk submits the second.
		 */
		u64 lower64 = get_unaligned_be64(rctx->iv_buf + 8);
		u32 nblocks = DIV_ROUND_UP(req->cryptlen,
					  CMH_AES_BLOCK_SIZE);
		u64 bwrap = lower64 ? (~lower64 + 1ULL) : U64_MAX;

		if (nblocks > bwrap) {
			u32 chunk1 = (u32)bwrap * CMH_AES_BLOCK_SIZE;
			u64 upper64;

			/* Prepare second IV for chained submission */
			rctx->iv2_buf = kmalloc(info->ivsize, gfp);
			if (!rctx->iv2_buf) {
				ret = -ENOMEM;
				goto out_unmap_iv;
			}
			upper64 = get_unaligned_be64(rctx->iv_buf);
			put_unaligned_be64(upper64 + 1, rctx->iv2_buf);
			put_unaligned_be64(0, rctx->iv2_buf + 8);

			rctx->iv2_dma =
				cmh_dma_map_single(rctx->iv2_buf,
						   info->ivsize,
						   DMA_TO_DEVICE);
			if (cmh_dma_map_error(rctx->iv2_dma)) {
				ret = -ENOMEM;
				goto out_free_iv2;
			}

			/* Store state for the chained second submission */
			rctx->ctr_chunk1_len = chunk1;
			rctx->core_id = core_id;
			rctx->target_mbx = target_mbx;
			rctx->key_ref = key_ref;

			/* First transaction: only chunk1 */
			vcq_add_aes_final(&cmds[idx++], core_id,
					  (u64)rctx->in_dma,
					  (u64)rctx->out_dma, chunk1);
		} else {
			/* No wrap: single FINAL with all data */
			vcq_add_aes_final(&cmds[idx++], core_id,
					  (u64)rctx->in_dma,
					  (u64)rctx->out_dma,
					  req->cryptlen);
		}
	} else {
		vcq_add_aes_final(&cmds[idx++], core_id,
				  (u64)rctx->in_dma,
				  (u64)rctx->out_dma, req->cryptlen);
	}

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_AES_MAX_PACKED, target_mbx,
					    cmh_aes_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_cleanup_all;

	return -EINPROGRESS;

out_cleanup_all:
	if (rctx->iv2_buf) {
		cmh_dma_unmap_single(rctx->iv2_dma, info->ivsize,
				     DMA_TO_DEVICE);
	}
out_free_iv2:
	kfree(rctx->iv2_buf);
out_unmap_iv:
	if (info->ivsize > 0)
		cmh_dma_unmap_single(rctx->iv_dma, info->ivsize,
				     DMA_TO_DEVICE);
out_free_iv:
	kfree(rctx->iv_buf);
out_unmap_out:
	cmh_dma_unmap_single(rctx->out_dma, req->cryptlen, DMA_FROM_DEVICE);
out_free_out:
	kfree_sensitive(rctx->out_buf);
out_unmap_in:
	cmh_dma_unmap_single(rctx->in_dma, req->cryptlen, DMA_TO_DEVICE);
out_free_in:
	kfree_sensitive(rctx->in_buf);
	return ret;
}

static int cmh_aes_encrypt(struct skcipher_request *req)
{
	return cmh_aes_crypt(req, AES_OP_ENCRYPT);
}

static int cmh_aes_decrypt(struct skcipher_request *req)
{
	return cmh_aes_crypt(req, AES_OP_DECRYPT);
}

/* Registration */

static struct cmh_aes_alg_drv aes_drv_algs[ARRAY_SIZE(aes_algs)];

/**
 * cmh_aes_register() - Register AES-CBC/CTR/ECB/XTS skcipher algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_aes_register(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++) {
		const struct cmh_aes_alg_info *info = &aes_algs[i];
		struct cmh_aes_alg_drv *drv = &aes_drv_algs[i];
		struct skcipher_alg *alg = &drv->alg;

		drv->info = info;

		memset(alg, 0, sizeof(*alg));

		alg->setkey      = cmh_aes_setkey;
		alg->encrypt     = cmh_aes_encrypt;
		alg->decrypt     = cmh_aes_decrypt;
		alg->init        = cmh_aes_init_tfm;
		alg->exit        = cmh_aes_exit_tfm;
		alg->min_keysize = info->min_keysize;
		alg->max_keysize = info->max_keysize;
		alg->ivsize      = info->ivsize;

		strscpy(alg->base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->base.cra_priority  = 300;
		alg->base.cra_flags     = CRYPTO_ALG_KERN_DRIVER_ONLY |
					  CRYPTO_ALG_ASYNC;
		alg->base.cra_blocksize = aes_is_stream_mode(info->aes_mode)
					  ? 1 : CMH_AES_BLOCK_SIZE;
		alg->base.cra_ctxsize  = sizeof(struct cmh_aes_tfm_ctx);
		alg->base.cra_module   = THIS_MODULE;

		ret = crypto_register_skcipher(alg);
		if (ret) {
			dev_err(cmh_dev(), "cmh_aes: failed to register %s (rc=%d)\n",
				info->alg_name, ret);
			goto err_unregister;
		}

		dev_dbg(cmh_dev(), "cmh_aes: registered %s\n", info->alg_name);
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_skcipher(&aes_drv_algs[i].alg);
	return ret;
}

/**
 * cmh_aes_unregister() - Unregister AES skcipher algorithms from the crypto framework
 */
void cmh_aes_unregister(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++) {
		crypto_unregister_skcipher(&aes_drv_algs[i].alg);
		dev_dbg(cmh_dev(), "cmh_aes: unregistered %s\n", aes_algs[i].alg_name);
	}
}
