// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API ChaCha20-Poly1305 AEAD Driver (RFC 7539)
 *
 * Registers "rfc7539(chacha20,poly1305)" as an AEAD algorithm with the
 * Linux crypto subsystem, backed by the CMH CCP core.
 *
 * VCQ sequence:
 *   [SYS_CMD_WRITE] + CCP_CMD_AEAD_INIT + [CCP_CMD_AAD_FINAL]
 *   + CCP_CMD_FINAL + CCP_CMD_FLUSH
 *
 * The RFC 7539 AEAD interface passes a 12-byte nonce via req->iv.
 * The CCP core expects a 16-byte ctrnonce (4-byte LE counter + 12-byte
 * nonce).  We prepend a zero counter (per RFC 7539 S2.8: counter 0
 * generates the Poly1305 key, counter 1 starts encryption -- the
 * CMH eSW handles this internally from the initial counter value of 0).
 *
 * Tag is always 16 bytes (Poly1305 authenticator).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/chacha.h>
#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
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

#define CCP_AEAD_IV_SIZE	12U	/* RFC 7539 nonce */
#define CCP_ESP_IV_SIZE		8U	/* RFC 7539 ESP nonce (4-byte salt at setkey) */
#define CCP_ESP_SALT_SIZE	4U
#define CCP_AEAD_TAG_SIZE	16U	/* Poly1305 tag */

struct cmh_ccp_aead_tfm_ctx {
	struct cmh_key_ctx key;
	u32 authsize;
	u8 salt[CCP_ESP_SALT_SIZE];	/* ESP salt (unused for rfc7539) */
};

/* Per-request context (lives in aead_request::__ctx) */

/*
 * Maximum payload commands:
 *   [SYS_CMD_WRITE] + CCP_CMD_AEAD_INIT + CCP_CMD_AAD_FINAL
 *   + CCP_CMD_FINAL + FLUSH = 5
 */
#define CMH_CCP_AEAD_MAX_PAYLOAD	5
#define CMH_CCP_AEAD_MAX_PACKED		(CMH_CCP_AEAD_MAX_PAYLOAD * 2)

struct cmh_ccp_aead_reqctx {
	dma_addr_t in_dma;
	dma_addr_t out_dma;
	dma_addr_t iv_dma;
	dma_addr_t key_dma;
	dma_addr_t aad_dma;
	dma_addr_t tag_dma;
	u8 *in_buf;
	u8 *out_buf;
	u8 *iv_buf;
	u8 *aad_buf;
	u8 *tag_buf;
	u32 cryptlen;
	u32 assoclen;
	u32 authsize;
	u32 keylen;
	bool encrypting;
	struct vcq_cmd packed[CMH_CCP_AEAD_MAX_PACKED];
};

/* VCQ Builders -- CCP AEAD-specific */

static void vcq_add_ccp_aead_init(struct vcq_cmd *slot, u32 core_id, u64 key_ref,
				  u64 ctrnonce_dma, u32 keylen, u32 op)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_AEAD_INIT);
	slot->hwc.ccp.cmd_aead.key = key_ref;
	slot->hwc.ccp.cmd_aead.ctrnonce = ctrnonce_dma;
	slot->hwc.ccp.cmd_aead.keylen = keylen;
	slot->hwc.ccp.cmd_aead.ctrnoncelen = CCP_CTRNONCE_SIZE;
	slot->hwc.ccp.cmd_aead.op = op;
}

static void vcq_add_ccp_aad_final(struct vcq_cmd *slot, u32 core_id, u64 aad_dma,
				  u32 aadlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_AAD_FINAL);
	slot->hwc.ccp.cmd_aad_final.aad = aad_dma;
	slot->hwc.ccp.cmd_aad_final.aadlen = aadlen;
}

static void vcq_add_ccp_aead_final(struct vcq_cmd *slot, u32 core_id, u64 input_dma,
				   u64 output_dma, u64 tag_dma,
				   u32 iolen, u32 taglen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, CCP_CMD_FINAL);
	slot->hwc.ccp.cmd_final.input = input_dma;
	slot->hwc.ccp.cmd_final.output = output_dma;
	slot->hwc.ccp.cmd_final.tag = tag_dma;
	slot->hwc.ccp.cmd_final.iolen = iolen;
	slot->hwc.ccp.cmd_final.taglen = taglen;
}

/* setkey */
static int cmh_ccp_aead_setkey(struct crypto_aead *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct cmh_ccp_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	/* RFC 7539 AEAD requires 32-byte key */
	if (keylen != CHACHA_KEY_SIZE)
		return -EINVAL;

	return cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_CCP);
}

static int cmh_ccp_aead_setauthsize(struct crypto_aead *tfm,
				    unsigned int authsize)
{
	struct cmh_ccp_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);

	/* Poly1305 tag is always 16 bytes */
	if (authsize != CCP_AEAD_TAG_SIZE)
		return -EINVAL;

	tctx->authsize = authsize;
	return 0;
}

static int cmh_ccp_aead_init_tfm(struct crypto_aead *tfm)
{
	struct cmh_ccp_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);

	memset(tctx, 0, sizeof(*tctx));
	tctx->authsize = CCP_AEAD_TAG_SIZE;
	crypto_aead_set_reqsize(tfm, sizeof(struct cmh_ccp_aead_reqctx));
	return 0;
}

static void cmh_ccp_aead_exit_tfm(struct crypto_aead *tfm)
{
	struct cmh_ccp_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);

	cmh_key_destroy(&tctx->key);
}

/* DMA unmap helper */
static void cmh_ccp_aead_unmap_dma(struct cmh_ccp_aead_reqctx *rctx)
{
	cmh_dma_unmap_single(rctx->iv_dma, CCP_CTRNONCE_SIZE, DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->tag_dma, rctx->authsize,
			     rctx->encrypting ? DMA_FROM_DEVICE :
					       DMA_TO_DEVICE);
	if (rctx->cryptlen > 0) {
		cmh_dma_unmap_single(rctx->out_dma, rctx->cryptlen,
				     DMA_FROM_DEVICE);
		cmh_dma_unmap_single(rctx->in_dma, rctx->cryptlen,
				     DMA_TO_DEVICE);
	}
	if (rctx->assoclen > 0)
		cmh_dma_unmap_single(rctx->aad_dma, rctx->assoclen,
				     DMA_TO_DEVICE);
}

static void cmh_ccp_aead_free_bufs(struct cmh_ccp_aead_reqctx *rctx)
{
	kfree(rctx->iv_buf);
	rctx->iv_buf = NULL;
	kfree(rctx->tag_buf);
	rctx->tag_buf = NULL;
	kfree_sensitive(rctx->out_buf);
	rctx->out_buf = NULL;
	kfree_sensitive(rctx->in_buf);
	rctx->in_buf = NULL;
	kfree(rctx->aad_buf);
	rctx->aad_buf = NULL;
}

static void cmh_ccp_aead_complete(void *data, int error)
{
	struct aead_request *req = data;
	struct cmh_ccp_aead_reqctx *rctx = aead_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	cmh_ccp_aead_unmap_dma(rctx);

	/*
	 * Map HW error on decrypt to -EBADMSG.  The eSW CCP core uses a
	 * single error code (-EIO) for both authentication failures and
	 * other core errors (e.g. DMA timeout), so we cannot distinguish
	 * them from the MBX_STATUS alone.  In practice the only error
	 * during a well-formed AEAD decrypt is auth-tag mismatch; a DMA
	 * timeout would indicate a fatal HW problem where -EBADMSG vs
	 * -EIO is moot.  The kernel crypto API requires -EBADMSG for
	 * AEAD authentication failures.
	 */
	if (error == -EIO && !rctx->encrypting)
		error = -EBADMSG;

	if (!error) {
		if (rctx->cryptlen > 0)
			scatterwalk_map_and_copy(rctx->out_buf, req->dst,
						 req->assoclen,
						rctx->cryptlen, 1);
		if (rctx->encrypting)
			scatterwalk_map_and_copy(rctx->tag_buf, req->dst,
						 req->assoclen +
						rctx->cryptlen,
						rctx->authsize, 1);
	}

	cmh_ccp_aead_free_bufs(rctx);
	cmh_complete(&req->base, error);
}

/*
 * Core AEAD encrypt/decrypt -- async path.
 *
 * Encrypt: plaintext -> ciphertext + 16-byte tag
 * Decrypt: ciphertext + tag -> plaintext (tag verified by CMH eSW)
 *
 * VCQ: [SYS_CMD_WRITE] + AEAD_INIT + [AAD_FINAL] + FINAL + FLUSH
 */
static int cmh_ccp_aead_crypt(struct aead_request *req, u32 ccp_op)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cmh_ccp_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	struct cmh_ccp_aead_reqctx *rctx = aead_request_ctx(req);
	struct vcq_cmd cmds[CMH_CCP_AEAD_MAX_PAYLOAD];
	u64 key_ref;
	u32 keylen, authsize, cryptlen;
	struct core_dispatch d;
	s32 target_mbx;
	u32 core_id;
	u32 idx;
	int ret;
	gfp_t gfp;

	if (tctx->key.mode == CMH_KEY_NONE)
		return -ENOKEY;

	authsize = tctx->authsize;

	if (ccp_op == CCP_OP_ENCRYPT) {
		cryptlen = req->cryptlen;
	} else {
		if (req->cryptlen < authsize)
			return -EINVAL;
		cryptlen = req->cryptlen - authsize;
	}

	/*
	 * HW uses a proprietary LLI scatter-gather format that is
	 * incompatible with struct scatterlist, so the payload is
	 * linearised into contiguous buffers for DMA.  Cap total
	 * size to prevent excessive memory consumption.
	 */
	if ((u64)cryptlen + req->assoclen > SZ_1M)
		return -EINVAL;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->cryptlen = cryptlen;
	rctx->assoclen = req->assoclen;
	rctx->authsize = authsize;
	rctx->encrypting = (ccp_op == CCP_OP_ENCRYPT);

	/*
	 * rfc7539esp: the last ivsize (8) bytes of the AAD region are the
	 * IV/nonce, not actual associated data.  Subtract them so HW only
	 * authenticates the real AAD.
	 */
	if (crypto_aead_ivsize(tfm) == CCP_ESP_IV_SIZE) {
		if (rctx->assoclen < CCP_ESP_IV_SIZE)
			return -EINVAL;
		rctx->assoclen -= CCP_ESP_IV_SIZE;
	}

	/* Linearise AAD */
	if (rctx->assoclen > 0) {
		rctx->aad_buf = kmalloc(rctx->assoclen, gfp);
		if (!rctx->aad_buf)
			return -ENOMEM;
		scatterwalk_map_and_copy(rctx->aad_buf, req->src,
					 0, rctx->assoclen, 0);
		rctx->aad_dma = cmh_dma_map_single(rctx->aad_buf,
						   rctx->assoclen,
						    DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->aad_dma)) {
			ret = -ENOMEM;
			goto out_free_aad;
		}
	}

	/* Linearise input */
	if (cryptlen > 0) {
		rctx->in_buf = kmalloc(cryptlen, gfp);
		if (!rctx->in_buf) {
			ret = -ENOMEM;
			goto out_unmap_aad;
		}
		scatterwalk_map_and_copy(rctx->in_buf, req->src,
					 req->assoclen, cryptlen, 0);
		rctx->in_dma = cmh_dma_map_single(rctx->in_buf, cryptlen,
						  DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->in_dma)) {
			ret = -ENOMEM;
			goto out_free_in;
		}
	}

	/* Allocate output buffer */
	if (cryptlen > 0) {
		rctx->out_buf = kmalloc(cryptlen, gfp);
		if (!rctx->out_buf) {
			ret = -ENOMEM;
			goto out_unmap_in;
		}
		rctx->out_dma = cmh_dma_map_single(rctx->out_buf, cryptlen,
						   DMA_FROM_DEVICE);
		if (cmh_dma_map_error(rctx->out_dma)) {
			ret = -ENOMEM;
			goto out_free_out;
		}
	}

	/* Tag buffer */
	rctx->tag_buf = kmalloc(authsize, gfp);
	if (!rctx->tag_buf) {
		ret = -ENOMEM;
		goto out_unmap_out;
	}

	if (!rctx->encrypting) {
		scatterwalk_map_and_copy(rctx->tag_buf, req->src,
					 req->assoclen + cryptlen,
					authsize, 0);
	} else {
		memset(rctx->tag_buf, 0, authsize);
	}

	rctx->tag_dma = cmh_dma_map_single(rctx->tag_buf, authsize,
					   rctx->encrypting ?
					    DMA_FROM_DEVICE : DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->tag_dma)) {
		ret = -ENOMEM;
		goto out_free_tag;
	}

	/* Build 16-byte ctrnonce: 4-byte zero counter + 12-byte nonce.
	 * rfc7539:    counter(4) | req->iv(12)
	 * rfc7539esp: counter(4) | salt(4) | req->iv(8)
	 */
	rctx->iv_buf = kzalloc(CCP_CTRNONCE_SIZE, gfp);
	if (!rctx->iv_buf) {
		ret = -ENOMEM;
		goto out_unmap_tag;
	}
	if (crypto_aead_ivsize(tfm) == CCP_ESP_IV_SIZE) {
		memcpy(rctx->iv_buf + CCP_CHACHA_CTR_LEN,
		       tctx->salt, CCP_ESP_SALT_SIZE);
		memcpy(rctx->iv_buf + CCP_CHACHA_CTR_LEN + CCP_ESP_SALT_SIZE,
		       req->iv, CCP_ESP_IV_SIZE);
	} else {
		memcpy(rctx->iv_buf + CCP_CHACHA_CTR_LEN,
		       req->iv, CCP_AEAD_IV_SIZE);
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

	/* AEAD_INIT */
	vcq_add_ccp_aead_init(&cmds[idx++], core_id, key_ref,
			      (u64)rctx->iv_dma, keylen, ccp_op);

	/* AAD_FINAL if we have associated data */
	if (rctx->assoclen > 0)
		vcq_add_ccp_aad_final(&cmds[idx++], core_id,
				      (u64)rctx->aad_dma, rctx->assoclen);

	/* FINAL with tag */
	vcq_add_ccp_aead_final(&cmds[idx++], core_id,
			       cryptlen > 0 ? (u64)rctx->in_dma : 0,
			       cryptlen > 0 ? (u64)rctx->out_dma : 0,
			       (u64)rctx->tag_dma, cryptlen, authsize);

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_CCP_AEAD_MAX_PACKED,
					    target_mbx,
					    cmh_ccp_aead_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_cleanup_all;

	return -EINPROGRESS;

out_cleanup_all:
	cmh_dma_unmap_single(rctx->iv_dma, CCP_CTRNONCE_SIZE, DMA_TO_DEVICE);
out_free_iv:
	kfree(rctx->iv_buf);
out_unmap_tag:
	cmh_dma_unmap_single(rctx->tag_dma, authsize,
			     rctx->encrypting ? DMA_FROM_DEVICE :
					       DMA_TO_DEVICE);
out_free_tag:
	kfree(rctx->tag_buf);
out_unmap_out:
	if (cryptlen > 0)
		cmh_dma_unmap_single(rctx->out_dma, cryptlen, DMA_FROM_DEVICE);
out_free_out:
	kfree_sensitive(rctx->out_buf);
out_unmap_in:
	if (cryptlen > 0)
		cmh_dma_unmap_single(rctx->in_dma, cryptlen, DMA_TO_DEVICE);
out_free_in:
	kfree_sensitive(rctx->in_buf);
out_unmap_aad:
	if (rctx->assoclen > 0)
		cmh_dma_unmap_single(rctx->aad_dma, rctx->assoclen,
				     DMA_TO_DEVICE);
out_free_aad:
	kfree(rctx->aad_buf);
	return ret;
}

static int cmh_ccp_aead_encrypt(struct aead_request *req)
{
	return cmh_ccp_aead_crypt(req, CCP_OP_ENCRYPT);
}

static int cmh_ccp_aead_decrypt(struct aead_request *req)
{
	return cmh_ccp_aead_crypt(req, CCP_OP_DECRYPT);
}

/* -- rfc7539esp: ESP variant with 4-byte salt + 8-byte IV --------------- */

/*
 * ESP setkey: 36 bytes = 32-byte ChaCha20 key + 4-byte salt.
 * The salt is prepended to the 8-byte per-packet IV from the ESP header
 * to form the 12-byte RFC 7539 nonce.
 */
static int cmh_ccp_esp_setkey(struct crypto_aead *tfm, const u8 *key,
			      unsigned int keylen)
{
	struct cmh_ccp_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);

	if (keylen != CHACHA_KEY_SIZE + CCP_ESP_SALT_SIZE)
		return -EINVAL;

	memcpy(tctx->salt, key + CHACHA_KEY_SIZE, CCP_ESP_SALT_SIZE);
	return cmh_key_setkey_raw(&tctx->key, key, CHACHA_KEY_SIZE, CORE_ID_CCP);
}

/* Registration */

static struct aead_alg cmh_rfc7539_alg = {
	.setkey      = cmh_ccp_aead_setkey,
	.setauthsize = cmh_ccp_aead_setauthsize,
	.encrypt     = cmh_ccp_aead_encrypt,
	.decrypt     = cmh_ccp_aead_decrypt,
	.init        = cmh_ccp_aead_init_tfm,
	.exit        = cmh_ccp_aead_exit_tfm,
	.ivsize      = CCP_AEAD_IV_SIZE,
	.maxauthsize = CCP_AEAD_TAG_SIZE,
	.base        = {
		.cra_name        = "rfc7539(chacha20,poly1305)",
		.cra_driver_name = "cri-cmh-rfc7539-chacha20-poly1305",
		.cra_priority    = 300,
		.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
				   CRYPTO_ALG_ASYNC,
		.cra_blocksize   = 1,
		.cra_ctxsize     = sizeof(struct cmh_ccp_aead_tfm_ctx),
		.cra_module      = THIS_MODULE,
	},
};

static struct aead_alg cmh_rfc7539esp_alg = {
	.setkey      = cmh_ccp_esp_setkey,
	.setauthsize = cmh_ccp_aead_setauthsize,
	.encrypt     = cmh_ccp_aead_encrypt,
	.decrypt     = cmh_ccp_aead_decrypt,
	.init        = cmh_ccp_aead_init_tfm,
	.exit        = cmh_ccp_aead_exit_tfm,
	.ivsize      = CCP_ESP_IV_SIZE,
	.maxauthsize = CCP_AEAD_TAG_SIZE,
	.base        = {
		.cra_name        = "rfc7539esp(chacha20,poly1305)",
		.cra_driver_name = "cri-cmh-rfc7539esp-chacha20-poly1305",
		.cra_priority    = 300,
		.cra_flags       = CRYPTO_ALG_KERN_DRIVER_ONLY |
				   CRYPTO_ALG_ASYNC,
		.cra_blocksize   = 1,
		.cra_ctxsize     = sizeof(struct cmh_ccp_aead_tfm_ctx),
		.cra_module      = THIS_MODULE,
	},
};

/**
 * cmh_ccp_aead_register() - Register ChaCha20-Poly1305 AEAD algorithm with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_ccp_aead_register(void)
{
	int ret;

	ret = crypto_register_aead(&cmh_rfc7539_alg);
	if (ret) {
		dev_err(cmh_dev(), "cmh_ccp_aead: failed to register rfc7539 (rc=%d)\n",
			ret);
		return ret;
	}
	dev_dbg(cmh_dev(), "cmh_ccp_aead: registered rfc7539(chacha20,poly1305)\n");

	ret = crypto_register_aead(&cmh_rfc7539esp_alg);
	if (ret) {
		dev_err(cmh_dev(), "cmh_ccp_aead: failed to register rfc7539esp (rc=%d)\n",
			ret);
		crypto_unregister_aead(&cmh_rfc7539_alg);
		return ret;
	}
	dev_dbg(cmh_dev(), "cmh_ccp_aead: registered rfc7539esp(chacha20,poly1305)\n");

	return 0;
}

/**
 * cmh_ccp_aead_unregister() - Unregister ChaCha20-Poly1305 AEAD algorithms
 */
void cmh_ccp_aead_unregister(void)
{
	crypto_unregister_aead(&cmh_rfc7539esp_alg);
	crypto_unregister_aead(&cmh_rfc7539_alg);
	dev_dbg(cmh_dev(), "cmh_ccp_aead: unregistered rfc7539/rfc7539esp\n");
}
