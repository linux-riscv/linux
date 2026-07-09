// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API SM4 AEAD Driver (GCM/CCM)
 *
 * Registers AEAD algorithms with the Linux crypto subsystem:
 *   gcm(sm4), ccm(sm4)
 *
 * GCM: SM4_CMD_INIT(mode=GCM) + [AAD_FINAL] + SM4_CMD_FINAL + FLUSH
 * CCM: SM4_CMD_CCM_INIT + [AAD_FINAL] + SM4_CMD_FINAL + FLUSH
 *   - SM4 CCM uses a distinct sm4_cmd_ccm_init struct
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/cipher.h>
#include <crypto/scatterwalk.h>
#include <crypto/utils.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_sm4.h"
#include "cmh_vcq.h"
#include "cmh_sm4_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/*
 * GCM IV contract:
 *
 * The SM4 core requires exactly 16 bytes loaded into its IV register.
 * For standard 96-bit nonce GCM, the driver passes:
 *
 *   IV[0..11]  = user-supplied 12-byte nonce
 *   IV[12..15] = 0x00000000
 *
 * The hardware internally sets the last 32 bits to the big-endian
 * counter value 1 (forming J0 = nonce || 0x00000001) before
 * processing AAD.  The driver must NOT pre-set the counter.
 *
 * If the IV format is incorrect, GCM authentication will fail
 * (encrypt produces wrong ciphertext/tag, decrypt rejects).
 */
#define SM4_GCM_IV_SIZE		12U	/* GCM nonce size (standard) */
#define SM4_GCM_HW_IV_SIZE	16U	/* HW requires 16-byte IV buffer */
#define SM4_GCM_TAG_SIZE	16U

/* CCM: callers pass a 16-byte IV in RFC 3610 format:
 * iv[0] = L-1, iv[1..14-iv[0]] = nonce, rest = counter (zeroed).
 * Nonce length = 14 - iv[0], range 7..13.
 */
#define SM4_CCM_IV_SIZE	16U

enum cmh_sm4_aead_type {
	CMH_SM4_AEAD_GCM,
	CMH_SM4_AEAD_CCM,
};

struct cmh_sm4_aead_info {
	enum cmh_sm4_aead_type type;
	u32         sm4_mode;
	u32         ivsize;
	u32         maxauthsize;
	const char *alg_name;
	const char *drv_name;
};

static const struct cmh_sm4_aead_info sm4_aead_algs[] = {
	{ CMH_SM4_AEAD_GCM, SM4_MODE_GCM, SM4_GCM_IV_SIZE,
	  SM4_GCM_TAG_SIZE, "gcm(sm4)", "cri-cmh-gcm-sm4" },
	{ CMH_SM4_AEAD_CCM, SM4_MODE_CCM, SM4_CCM_IV_SIZE,
	  SM4_GCM_TAG_SIZE, "ccm(sm4)", "cri-cmh-ccm-sm4" },
};

struct cmh_sm4_aead_tfm_ctx {
	struct cmh_key_ctx key;
	u32 authsize;
	struct crypto_cipher *sw_cipher;	/* CCM empty-input fallback */
};

/* Per-request context (lives in aead_request::__ctx) */

#define CMH_SM4_AEAD_MAX_PAYLOAD	5
#define CMH_SM4_AEAD_MAX_PACKED		(CMH_SM4_AEAD_MAX_PAYLOAD * 2)

struct cmh_sm4_aead_reqctx {
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
	u32 iv_map_len;
	u32 keylen;
	bool encrypting;
	bool empty_gcm_fallback;
	struct vcq_cmd packed[CMH_SM4_AEAD_MAX_PACKED];
};

struct cmh_sm4_aead_drv {
	struct aead_alg                  alg;
	const struct cmh_sm4_aead_info  *info;
};

static const struct cmh_sm4_aead_info *
cmh_sm4_aead_get_info(struct crypto_aead *tfm)
{
	struct aead_alg *alg = crypto_aead_alg(tfm);

	return container_of(alg, struct cmh_sm4_aead_drv, alg)->info;
}

/* VCQ Builders -- SM4 AEAD-specific */

static void vcq_add_sm4_aead_init(struct vcq_cmd *slot, u32 core_id, u64 key_ref,
				  u64 iv_dma, u32 keylen, u32 ivlen,
				  u32 mode, u32 op, u32 aadlen, u32 iolen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_INIT);
	slot->hwc.sm4.cmd_init.key = key_ref;
	slot->hwc.sm4.cmd_init.iv = iv_dma;
	slot->hwc.sm4.cmd_init.keylen = keylen;
	slot->hwc.sm4.cmd_init.ivlen = ivlen;
	slot->hwc.sm4.cmd_init.mode = mode;
	slot->hwc.sm4.cmd_init.op = op;
	slot->hwc.sm4.cmd_init.aadlen = aadlen;
	slot->hwc.sm4.cmd_init.iolen = iolen;
}

static void vcq_add_sm4_ccm_init(struct vcq_cmd *slot, u32 core_id, u64 key_ref,
				 u64 nonce_dma, u32 keylen, u32 noncelen,
				 u32 op, u32 aadlen, u32 iolen, u32 taglen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_CCM_INIT);
	slot->hwc.sm4.cmd_ccm_init.key = key_ref;
	slot->hwc.sm4.cmd_ccm_init.nonce = nonce_dma;
	slot->hwc.sm4.cmd_ccm_init.keylen = keylen;
	slot->hwc.sm4.cmd_ccm_init.noncelen = noncelen;
	slot->hwc.sm4.cmd_ccm_init.op = op;
	slot->hwc.sm4.cmd_ccm_init.aadlen = aadlen;
	slot->hwc.sm4.cmd_ccm_init.iolen = iolen;
	slot->hwc.sm4.cmd_ccm_init.taglen = taglen;
}

static void vcq_add_sm4_aad_final(struct vcq_cmd *slot, u32 core_id, u64 aad_dma,
				  u32 aadlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_AAD_FINAL);
	slot->hwc.sm4.cmd_aad_final.data = aad_dma;
	slot->hwc.sm4.cmd_aad_final.datalen = aadlen;
}

static void vcq_add_sm4_aead_final(struct vcq_cmd *slot, u32 core_id, u64 input_dma,
				   u64 output_dma, u64 tag_dma,
				   u32 iolen, u32 taglen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_FINAL);
	slot->hwc.sm4.cmd_final.input = input_dma;
	slot->hwc.sm4.cmd_final.output = output_dma;
	slot->hwc.sm4.cmd_final.tag = tag_dma;
	slot->hwc.sm4.cmd_final.iolen = iolen;
	slot->hwc.sm4.cmd_final.taglen = taglen;
}

/* setkey */
static int cmh_sm4_aead_setkey(struct crypto_aead *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	/* SM4 always uses 128-bit keys */
	if (keylen != CMH_SM4_KEY_SIZE)
		return -EINVAL;

	if (tctx->sw_cipher) {
		int ret;

		ret = crypto_cipher_setkey(tctx->sw_cipher, key, keylen);
		if (ret)
			return ret;
	}

	return cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_SM4);
}

static int cmh_sm4_aead_setauthsize(struct crypto_aead *tfm,
				    unsigned int authsize)
{
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	const struct cmh_sm4_aead_info *info = cmh_sm4_aead_get_info(tfm);

	if (info->type == CMH_SM4_AEAD_GCM) {
		/* eSW enforces taglen == 16 for SM4 GCM (EIP40_SM4_TAG_SIZE) */
		if (authsize != 16)
			return -EINVAL;
	} else {
		/* CCM: accept 4, 6, 8, 10, 12, 14, 16 per RFC 3610 */
		if (authsize < 4 || authsize > 16 || (authsize & 1))
			return -EINVAL;
	}

	tctx->authsize = authsize;
	return 0;
}

static int cmh_sm4_aead_init_tfm(struct crypto_aead *tfm)
{
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	const struct cmh_sm4_aead_info *info = cmh_sm4_aead_get_info(tfm);

	memset(tctx, 0, sizeof(*tctx));
	tctx->authsize = info->maxauthsize;

	if (info->type == CMH_SM4_AEAD_CCM) {
		struct crypto_cipher *ci;

		ci = crypto_alloc_cipher("sm4", 0, 0);
		if (IS_ERR(ci))
			return PTR_ERR(ci);
		tctx->sw_cipher = ci;
	}

	crypto_aead_set_reqsize(tfm, sizeof(struct cmh_sm4_aead_reqctx));
	return 0;
}

static void cmh_sm4_aead_exit_tfm(struct crypto_aead *tfm)
{
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);

	if (tctx->sw_cipher)
		crypto_free_cipher(tctx->sw_cipher);
	cmh_key_destroy(&tctx->key);
}

/* DMA unmap helper */
static void cmh_sm4_aead_unmap_dma(struct cmh_sm4_aead_reqctx *rctx)
{
	u32 tag_map_len;

	cmh_dma_unmap_single(rctx->iv_dma, rctx->iv_map_len, DMA_TO_DEVICE);
	tag_map_len = rctx->empty_gcm_fallback ?
		      SM4_GCM_HW_IV_SIZE : rctx->authsize;
	cmh_dma_unmap_single(rctx->tag_dma, tag_map_len,
			     (rctx->encrypting || rctx->empty_gcm_fallback) ?
			      DMA_FROM_DEVICE : DMA_TO_DEVICE);
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

static void cmh_sm4_aead_free_bufs(struct cmh_sm4_aead_reqctx *rctx)
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

static void cmh_sm4_aead_complete(void *data, int error)
{
	struct aead_request *req = data;
	struct cmh_sm4_aead_reqctx *rctx = aead_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	cmh_sm4_aead_unmap_dma(rctx);

	/*
	 * Map HW error on decrypt to -EBADMSG.  The eSW SM4 core uses a
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
		if (rctx->empty_gcm_fallback && !rctx->encrypting) {
			if (crypto_memneq(rctx->tag_buf, rctx->in_buf,
					  rctx->authsize))
				error = -EBADMSG;
		}
		if (!error && rctx->cryptlen > 0)
			scatterwalk_map_and_copy(rctx->out_buf, req->dst,
						 req->assoclen,
						rctx->cryptlen, 1);
		if (!error && rctx->encrypting)
			scatterwalk_map_and_copy(rctx->tag_buf, req->dst,
						 req->assoclen +
						rctx->cryptlen,
						rctx->authsize, 1);
	}

	cmh_sm4_aead_free_bufs(rctx);
	cmh_complete(&req->base, error);
}

/*
 * GCM empty-input fallback (SM4).
 *
 * When both AAD and plaintext are empty, GCM reduces to:
 *   tag = E(K, J0) where J0 = nonce || 0x00000001
 *
 * The eSW GCM engine rejects this degenerate case, so we compute it
 * via a single ECB block encryption of J0.
 *
 * VCQ: [SYS_CMD_WRITE] + SM4_CMD_INIT(ECB) + SM4_CMD_FINAL + FLUSH
 */
static int cmh_sm4_gcm_empty(struct aead_request *req, u32 sm4_op)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	struct cmh_sm4_aead_reqctx *rctx = aead_request_ctx(req);
	struct vcq_cmd cmds[CMH_SM4_AEAD_MAX_PAYLOAD];
	u64 key_ref;
	u32 keylen, authsize;
	struct core_dispatch d;
	s32 target_mbx;
	u32 core_id;
	u32 idx;
	int ret;
	gfp_t gfp;

	authsize = tctx->authsize;

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	memset(rctx, 0, sizeof(*rctx));
	rctx->cryptlen = 0;
	rctx->assoclen = 0;
	rctx->authsize = authsize;
	rctx->encrypting = (sm4_op == SM4_OP_ENCRYPT);
	rctx->empty_gcm_fallback = true;

	/* Build J0 = nonce || 0x00000001 in iv_buf */
	rctx->iv_buf = kzalloc(SM4_GCM_HW_IV_SIZE, gfp);
	if (!rctx->iv_buf)
		return -ENOMEM;
	memcpy(rctx->iv_buf, req->iv, SM4_GCM_IV_SIZE);
	rctx->iv_buf[15] = 0x01;
	rctx->iv_map_len = SM4_GCM_HW_IV_SIZE;

	rctx->iv_dma = cmh_dma_map_single(rctx->iv_buf, SM4_GCM_HW_IV_SIZE,
					  DMA_TO_DEVICE);
	if (cmh_dma_map_error(rctx->iv_dma)) {
		ret = -ENOMEM;
		goto out_free_iv;
	}

	/* Tag buffer -- receives E(K, J0) output */
	rctx->tag_buf = kzalloc(SM4_GCM_HW_IV_SIZE, gfp);
	if (!rctx->tag_buf) {
		ret = -ENOMEM;
		goto out_unmap_iv;
	}
	rctx->tag_dma = cmh_dma_map_single(rctx->tag_buf, SM4_GCM_HW_IV_SIZE,
					   DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->tag_dma)) {
		ret = -ENOMEM;
		goto out_free_tag;
	}

	/* For decrypt: read expected tag from request */
	if (!rctx->encrypting) {
		rctx->in_buf = kmalloc(authsize, gfp);
		if (!rctx->in_buf) {
			ret = -ENOMEM;
			goto out_unmap_tag;
		}
		scatterwalk_map_and_copy(rctx->in_buf, req->src, 0,
					 authsize, 0);
	}

	/* Resolve key */
	idx = 0;
	rctx->key_dma = tctx->key.raw.dma;
	vcq_add_sys_write(&cmds[idx++], SYS_REF_TEMP,
			  (u64)rctx->key_dma, SYS_REF_NONE,
			  tctx->key.raw.len,
			  tctx->key.raw.sys_type);
	key_ref = SYS_REF_TEMP;
	keylen = tctx->key.raw.len;
	d = cmh_core_select_instance(CMH_CORE_SM4);
	target_mbx = d.mbx_idx;
	core_id = d.core_id;

	/* ECB INIT: single block encryption of J0 */
	vcq_add_sm4_aead_init(&cmds[idx++], core_id, key_ref,
			      0, keylen, 0, SM4_MODE_ECB, SM4_OP_ENCRYPT,
			      0, SM4_GCM_HW_IV_SIZE);

	/* FINAL: J0 in, E(K,J0) out */
	vcq_add_sm4_aead_final(&cmds[idx++], core_id,
			       (u64)rctx->iv_dma, (u64)rctx->tag_dma,
			       0, SM4_GCM_HW_IV_SIZE, 0);

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_SM4_AEAD_MAX_PACKED,
					    target_mbx,
					    cmh_sm4_aead_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_free_in;

	return -EINPROGRESS;

out_free_in:
	kfree_sensitive(rctx->in_buf);
out_unmap_tag:
	cmh_dma_unmap_single(rctx->tag_dma, SM4_GCM_HW_IV_SIZE,
			     DMA_FROM_DEVICE);
out_free_tag:
	kfree(rctx->tag_buf);
out_unmap_iv:
	cmh_dma_unmap_single(rctx->iv_dma, SM4_GCM_HW_IV_SIZE, DMA_TO_DEVICE);
out_free_iv:
	kfree(rctx->iv_buf);
	return ret;
}

/*
 * CCM empty-input fallback (SM4).
 *
 * When both AAD and plaintext are empty, CCM reduces to:
 *   T  = E(K, B0)    -- CBC-MAC of the single formatting block
 *   S0 = E(K, A0)    -- CTR block zero
 *   tag = (T XOR S0)[0..authsize-1]
 *
 * The eSW rejects this degenerate case, so the driver computes it
 * synchronously via two crypto_cipher single-block encryptions.
 */
static int cmh_sm4_ccm_empty(struct aead_request *req, u32 sm4_op)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	u32 authsize = tctx->authsize;
	u8 b0[CMH_SM4_BLOCK_SIZE], a0[CMH_SM4_BLOCK_SIZE];
	u8 t[CMH_SM4_BLOCK_SIZE], s0[CMH_SM4_BLOCK_SIZE];
	u8 tag[CMH_SM4_BLOCK_SIZE];
	u8 L;
	u32 i;

	/* Defense-in-depth: iv[0] = L-1, valid L is 2..8 per RFC 3610 S2.1 */
	if (WARN_ON_ONCE(req->iv[0] < 1 || req->iv[0] > 7))
		return -EINVAL;

	L = req->iv[0] + 1;

	if (tctx->key.mode != CMH_KEY_RAW)
		return -EOPNOTSUPP;

	/* B0: flags || nonce || Q(=0).  Adata=0, t=authsize, q=L. */
	memset(b0, 0, CMH_SM4_BLOCK_SIZE);
	b0[0] = (u8)(8 * ((authsize - 2) / 2) + (L - 1));
	memcpy(&b0[1], &req->iv[1], 15 - L);

	/* A0: (L-1) || nonce || counter(=0) */
	memset(a0, 0, CMH_SM4_BLOCK_SIZE);
	a0[0] = (u8)(L - 1);
	memcpy(&a0[1], &req->iv[1], 15 - L);

	crypto_cipher_encrypt_one(tctx->sw_cipher, t, b0);
	crypto_cipher_encrypt_one(tctx->sw_cipher, s0, a0);

	for (i = 0; i < authsize; i++)
		tag[i] = t[i] ^ s0[i];

	if (sm4_op == SM4_OP_ENCRYPT) {
		scatterwalk_map_and_copy(tag, req->dst,
					 req->assoclen, authsize, 1);
	} else {
		u8 expected[CMH_SM4_BLOCK_SIZE];

		scatterwalk_map_and_copy(expected, req->src,
					 req->assoclen, authsize, 0);
		if (crypto_memneq(tag, expected, authsize))
			return -EBADMSG;
	}

	return 0;
}

static int cmh_sm4_aead_crypt(struct aead_request *req, u32 sm4_op)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cmh_sm4_aead_tfm_ctx *tctx = crypto_aead_ctx(tfm);
	const struct cmh_sm4_aead_info *info = cmh_sm4_aead_get_info(tfm);
	struct cmh_sm4_aead_reqctx *rctx = aead_request_ctx(req);
	struct vcq_cmd cmds[CMH_SM4_AEAD_MAX_PAYLOAD];
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

	if (sm4_op == SM4_OP_ENCRYPT) {
		cryptlen = req->cryptlen;
	} else {
		if (req->cryptlen < authsize)
			return -EINVAL;
		cryptlen = req->cryptlen - authsize;
	}

	/*
	 * Validate CCM IV format early -- the empty-input fallback and
	 * nonce extraction both depend on iv[0] being in range [1,7].
	 */
	if (info->type == CMH_SM4_AEAD_CCM) {
		if (req->iv[0] < 1 || req->iv[0] > 7)
			return -EINVAL;
	}

	/*
	 * The CMH eSW rejects SM4 GCM/CCM when both aadlen and iolen
	 * are zero.  For GCM, the tag is simply E(K, J0) -- use ECB
	 * fallback.  For CCM, compute tag = E(K,B0) XOR E(K,A0) in SW.
	 */
	if (cryptlen == 0 && req->assoclen == 0) {
		if (info->type == CMH_SM4_AEAD_GCM)
			return cmh_sm4_gcm_empty(req, sm4_op);
		return cmh_sm4_ccm_empty(req, sm4_op);
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
	rctx->encrypting = (sm4_op == SM4_OP_ENCRYPT);

	/* Linearise AAD */
	if (req->assoclen > 0) {
		rctx->aad_buf = kmalloc(req->assoclen, gfp);
		if (!rctx->aad_buf)
			return -ENOMEM;
		scatterwalk_map_and_copy(rctx->aad_buf, req->src,
					 0, req->assoclen, 0);
		rctx->aad_dma = cmh_dma_map_single(rctx->aad_buf,
						   req->assoclen,
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

	/* Map IV/nonce */
	if (info->type == CMH_SM4_AEAD_GCM) {
		rctx->iv_buf = kzalloc(SM4_GCM_HW_IV_SIZE, gfp);
		if (!rctx->iv_buf) {
			ret = -ENOMEM;
			goto out_unmap_tag;
		}
		memcpy(rctx->iv_buf, req->iv, SM4_GCM_IV_SIZE);
		rctx->iv_map_len = SM4_GCM_HW_IV_SIZE;
		rctx->iv_dma = cmh_dma_map_single(rctx->iv_buf,
						  rctx->iv_map_len,
						   DMA_TO_DEVICE);
	} else {
		u32 noncelen;

		if (req->iv[0] < 1 || req->iv[0] > 7) {
			ret = -EINVAL;
			goto out_unmap_tag;
		}
		noncelen = 14 - req->iv[0];

		rctx->iv_buf = kmemdup(req->iv + 1, noncelen, gfp);
		if (!rctx->iv_buf) {
			ret = -ENOMEM;
			goto out_unmap_tag;
		}
		rctx->iv_map_len = noncelen;
		rctx->iv_dma = cmh_dma_map_single(rctx->iv_buf,
						  rctx->iv_map_len,
						   DMA_TO_DEVICE);
	}
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
	d = cmh_core_select_instance(CMH_CORE_SM4);
	target_mbx = d.mbx_idx;
	core_id = d.core_id;

	/* Build INIT command */
	if (info->type == CMH_SM4_AEAD_CCM) {
		vcq_add_sm4_ccm_init(&cmds[idx++], core_id, key_ref,
				     (u64)rctx->iv_dma, keylen,
				     rctx->iv_map_len, sm4_op,
				     req->assoclen, cryptlen, authsize);
	} else {
		vcq_add_sm4_aead_init(&cmds[idx++], core_id, key_ref,
				      (u64)rctx->iv_dma, keylen,
				      SM4_GCM_HW_IV_SIZE, info->sm4_mode,
				      sm4_op, req->assoclen, cryptlen);
	}

	if (req->assoclen > 0)
		vcq_add_sm4_aad_final(&cmds[idx++], core_id,
				      (u64)rctx->aad_dma, req->assoclen);

	vcq_add_sm4_aead_final(&cmds[idx++], core_id,
			       cryptlen > 0 ? (u64)rctx->in_dma : 0,
			       cryptlen > 0 ? (u64)rctx->out_dma : 0,
			       (u64)rctx->tag_dma, cryptlen, authsize);

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_SM4_AEAD_MAX_PACKED,
					    target_mbx,
					    cmh_sm4_aead_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
	if (ret == -EBUSY)
		return -EBUSY;
	if (ret)
		goto out_cleanup_all;

	return -EINPROGRESS;

out_cleanup_all:
	cmh_dma_unmap_single(rctx->iv_dma, rctx->iv_map_len, DMA_TO_DEVICE);
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
	if (req->assoclen > 0)
		cmh_dma_unmap_single(rctx->aad_dma, req->assoclen,
				     DMA_TO_DEVICE);
out_free_aad:
	kfree(rctx->aad_buf);
	return ret;
}

static int cmh_sm4_aead_encrypt(struct aead_request *req)
{
	return cmh_sm4_aead_crypt(req, SM4_OP_ENCRYPT);
}

static int cmh_sm4_aead_decrypt(struct aead_request *req)
{
	return cmh_sm4_aead_crypt(req, SM4_OP_DECRYPT);
}

/* Registration */

static struct cmh_sm4_aead_drv sm4_aead_drv_algs[ARRAY_SIZE(sm4_aead_algs)];

/**
 * cmh_sm4_aead_register() - Register SM4-GCM/CCM AEAD algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_sm4_aead_register(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(sm4_aead_algs); i++) {
		const struct cmh_sm4_aead_info *info = &sm4_aead_algs[i];
		struct cmh_sm4_aead_drv *drv = &sm4_aead_drv_algs[i];
		struct aead_alg *alg = &drv->alg;

		drv->info = info;

		memset(alg, 0, sizeof(*alg));

		alg->setkey      = cmh_sm4_aead_setkey;
		alg->setauthsize = cmh_sm4_aead_setauthsize;
		alg->encrypt     = cmh_sm4_aead_encrypt;
		alg->decrypt     = cmh_sm4_aead_decrypt;
		alg->init        = cmh_sm4_aead_init_tfm;
		alg->exit        = cmh_sm4_aead_exit_tfm;
		alg->ivsize      = info->ivsize;
		alg->maxauthsize = info->maxauthsize;

		strscpy(alg->base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->base.cra_priority  = 300;
		alg->base.cra_flags     = CRYPTO_ALG_KERN_DRIVER_ONLY |
					  CRYPTO_ALG_ASYNC;
		alg->base.cra_blocksize = 1;
		alg->base.cra_ctxsize  = sizeof(struct cmh_sm4_aead_tfm_ctx);
		alg->base.cra_module   = THIS_MODULE;

		ret = crypto_register_aead(alg);
		if (ret) {
			dev_err(cmh_dev(), "cmh_sm4_aead: failed to register %s (rc=%d)\n",
				info->alg_name, ret);
			goto err_unregister;
		}

		dev_dbg(cmh_dev(), "cmh_sm4_aead: registered %s\n", info->alg_name);
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_aead(&sm4_aead_drv_algs[i].alg);
	return ret;
}

/**
 * cmh_sm4_aead_unregister() - Unregister SM4 AEAD algorithms from the crypto framework
 */
void cmh_sm4_aead_unregister(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sm4_aead_algs); i++) {
		crypto_unregister_aead(&sm4_aead_drv_algs[i].alg);
		dev_dbg(cmh_dev(), "cmh_sm4_aead: unregistered %s\n",
			sm4_aead_algs[i].alg_name);
	}
}
