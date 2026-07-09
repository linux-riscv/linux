// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API ChaCha20 (skcipher) Driver
 *
 * Registers the "chacha20" skcipher algorithm with the Linux crypto
 * subsystem, backed by the CMH CCP core.
 *
 * VCQ sequence:
 *   [SYS_CMD_WRITE] + CCP_CMD_CHACHA20_INIT + CCP_CMD_FINAL + CCP_CMD_FLUSH
 *
 * The CCP core expects a 16-byte counter+nonce (ctrnonce):
 *   bytes [0..3]  = 32-bit LE counter
 *   bytes [4..15] = 12-byte nonce
 *
 * The Linux chacha20 skcipher interface passes a 16-byte IV in the
 * same format, so we forward it directly.
 *
 * ChaCha20 is a stream cipher -- arbitrary plaintext lengths are
 * supported (no block-alignment requirement).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "cmh_ccp.h"
#include "cmh_vcq.h"
#include "cmh_ccp_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/* Per-transform context */

struct cmh_ccp_tfm_ctx {
	struct cmh_key_ctx key;
};

/* Per-request context (lives in skcipher_request::__ctx) */

/*
 * Maximum payload commands:
 *   [SYS_CMD_WRITE] + CCP_CMD_CHACHA20_INIT + CCP_CMD_FINAL + FLUSH = 4
 */
#define CMH_CCP_MAX_PAYLOAD	4
#define CMH_CCP_MAX_PACKED	(CMH_CCP_MAX_PAYLOAD * 2)

struct cmh_ccp_reqctx {
	dma_addr_t in_dma;
	dma_addr_t out_dma;
	dma_addr_t iv_dma;
	dma_addr_t key_dma;
	u8 *in_buf;
	u8 *out_buf;
	u8 *iv_buf;
	u32 cryptlen;
	u32 keylen;
	struct vcq_cmd packed[CMH_CCP_MAX_PACKED];
};

/* VCQ Builders -- ChaCha20-specific */

static void vcq_add_ccp_chacha_init(struct vcq_cmd *slot, u32 core_id, u64 key_ref,
				    u64 ctrnonce_dma, u32 keylen, u32 op)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_CHACHA20_INIT);
	slot->hwc.ccp.cmd_chacha.key = key_ref;
	slot->hwc.ccp.cmd_chacha.ctrnonce = ctrnonce_dma;
	slot->hwc.ccp.cmd_chacha.keylen = keylen;
	slot->hwc.ccp.cmd_chacha.ctrnoncelen = CCP_CTRNONCE_SIZE;
	slot->hwc.ccp.cmd_chacha.ctrlen = CCP_CHACHA_CTR_LEN;
	slot->hwc.ccp.cmd_chacha.op = op;
}

static void vcq_add_ccp_final(struct vcq_cmd *slot, u32 core_id, u64 input_dma,
			      u64 output_dma, u32 iolen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_FINAL);
	slot->hwc.ccp.cmd_final.input = input_dma;
	slot->hwc.ccp.cmd_final.output = output_dma;
	slot->hwc.ccp.cmd_final.tag = 0;
	slot->hwc.ccp.cmd_final.iolen = iolen;
	slot->hwc.ccp.cmd_final.taglen = 0;
}

/* skcipher Operations */
static int cmh_ccp_setkey(struct crypto_skcipher *tfm, const u8 *key,
			  unsigned int keylen)
{
	struct cmh_ccp_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	/* ChaCha20 requires 32-byte key per RFC 8439 */
	if (keylen != 32)
		return -EINVAL;

	return cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_CCP);
}

static int cmh_ccp_init_tfm(struct crypto_skcipher *tfm)
{
	struct cmh_ccp_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);

	memset(tctx, 0, sizeof(*tctx));
	crypto_skcipher_set_reqsize(tfm, sizeof(struct cmh_ccp_reqctx));
	return 0;
}

static void cmh_ccp_exit_tfm(struct crypto_skcipher *tfm)
{
	struct cmh_ccp_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);

	cmh_key_destroy(&tctx->key);
}

/* DMA unmap helper */
static void cmh_ccp_unmap_dma(struct cmh_ccp_reqctx *rctx)
{
	cmh_dma_unmap_single(rctx->iv_dma, CCP_CTRNONCE_SIZE, DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->out_dma, rctx->cryptlen, DMA_FROM_DEVICE);
	cmh_dma_unmap_single(rctx->in_dma, rctx->cryptlen, DMA_TO_DEVICE);
}

static void cmh_ccp_free_bufs(struct cmh_ccp_reqctx *rctx)
{
	kfree(rctx->iv_buf);
	rctx->iv_buf = NULL;
	kfree_sensitive(rctx->out_buf);
	rctx->out_buf = NULL;
	kfree_sensitive(rctx->in_buf);
	rctx->in_buf = NULL;
}

static void cmh_ccp_complete(void *data, int error)
{
	struct skcipher_request *req = data;
	struct cmh_ccp_reqctx *rctx = skcipher_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	cmh_ccp_unmap_dma(rctx);

	if (!error) {
		u32 counter, nblocks;

		scatterwalk_map_and_copy(rctx->out_buf, req->dst,
					 0, rctx->cryptlen, 1);

		/*
		 * Update the 32-bit LE block counter at IV[0..3].
		 * ChaCha20 processes 64-byte blocks; the nonce at
		 * IV[4..15] is unchanged.
		 */
		counter = get_unaligned_le32(req->iv);
		nblocks = DIV_ROUND_UP(rctx->cryptlen, 64);
		put_unaligned_le32(counter + nblocks, req->iv);
	}

	cmh_ccp_free_bufs(rctx);
	cmh_complete(&req->base, error);
}

/*
 * Core encrypt/decrypt -- builds a VCQ transaction and submits async.
 *
 * ChaCha20 is a stream cipher: encrypt and decrypt use the same
 * underlying XOR operation.
 */
static int cmh_ccp_crypt(struct skcipher_request *req, u32 ccp_op)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct cmh_ccp_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct cmh_ccp_reqctx *rctx = skcipher_request_ctx(req);
	struct vcq_cmd cmds[CMH_CCP_MAX_PAYLOAD];
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

	/* Limit linearisation buffers to avoid large allocations. */
	if (req->cryptlen > SZ_1M)
		return -EINVAL;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->cryptlen = req->cryptlen;

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

	rctx->iv_buf = kmemdup(req->iv, CCP_CTRNONCE_SIZE, gfp);
	if (!rctx->iv_buf) {
		ret = -ENOMEM;
		goto out_unmap_out;
	}

	rctx->iv_dma = cmh_dma_map_single(rctx->iv_buf, CCP_CTRNONCE_SIZE,
					  DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->iv_dma)) {
		ret = -ENOMEM;
		goto out_free_iv;
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
	d = cmh_core_select_instance(CMH_CORE_CCP);
	target_mbx = d.mbx_idx;
	core_id = d.core_id;

	vcq_add_ccp_chacha_init(&cmds[idx++], core_id, key_ref,
				(u64)rctx->iv_dma, keylen, ccp_op);

	vcq_add_ccp_final(&cmds[idx++], core_id, (u64)rctx->in_dma,
			  (u64)rctx->out_dma, req->cryptlen);

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_CCP_MAX_PACKED, target_mbx,
					    cmh_ccp_complete, req,
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
	cmh_dma_unmap_single(rctx->iv_dma, CCP_CTRNONCE_SIZE, DMA_TO_DEVICE);
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

static int cmh_ccp_encrypt(struct skcipher_request *req)
{
	return cmh_ccp_crypt(req, CCP_OP_ENCRYPT);
}

static int cmh_ccp_decrypt(struct skcipher_request *req)
{
	return cmh_ccp_crypt(req, CCP_OP_DECRYPT);
}

/* Registration */

static struct skcipher_alg cmh_chacha20_alg = {
	.setkey      = cmh_ccp_setkey,
	.encrypt     = cmh_ccp_encrypt,
	.decrypt     = cmh_ccp_decrypt,
	.init        = cmh_ccp_init_tfm,
	.exit        = cmh_ccp_exit_tfm,
	.min_keysize = 32,
	.max_keysize = 32,
	.ivsize      = CCP_CTRNONCE_SIZE,
	.base        = {
		.cra_name        = "chacha20",
		.cra_driver_name = "cri-cmh-chacha20",
		.cra_priority    = 300,
		.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
				   CRYPTO_ALG_ASYNC,
		.cra_blocksize   = 1,	/* stream cipher */
		.cra_ctxsize     = sizeof(struct cmh_ccp_tfm_ctx),
		.cra_module      = THIS_MODULE,
	},
};

/**
 * cmh_ccp_register() - Register ChaCha20 skcipher algorithm with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_ccp_register(void)
{
	int ret;

	ret = crypto_register_skcipher(&cmh_chacha20_alg);
	if (ret)
		dev_err(cmh_dev(), "cmh_ccp: failed to register chacha20 (rc=%d)\n", ret);
	else
		dev_dbg(cmh_dev(), "cmh_ccp: registered chacha20\n");

	return ret;
}

/**
 * cmh_ccp_unregister() - Unregister ChaCha20 skcipher algorithm from the crypto framework
 */
void cmh_ccp_unregister(void)
{
	crypto_unregister_skcipher(&cmh_chacha20_alg);
	dev_dbg(cmh_dev(), "cmh_ccp: unregistered chacha20\n");
}
