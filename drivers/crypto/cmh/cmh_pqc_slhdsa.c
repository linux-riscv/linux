// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SLH-DSA Signature Driver (sig_alg, synchronous)
 *
 * Registers SLH-DSA sig algorithms for all 12 parameter sets
 * (SHAKE/SHA2 x 128/192/256 x s/f) with sign and verify callbacks.
 *
 * Key format:
 *   Public key  = raw pk bytes (2*n bytes)
 *   Private key = raw sk bytes (4*n)
 *
 * Sign: src = message, dst = raw signature
 * Verify: src = raw signature, digest = message bytes
 *
 * Private keys are raw (written to SYS_REF_TEMP per-operation).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <crypto/sig.h>
#include <crypto/internal/sig.h>

#include "cmh_sys.h"
#include "cmh_qse_abi.h"
#include "cmh_hcq_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"
#include "cmh_pqc.h"

struct cmh_slhdsa_tfm_ctx {
	struct cmh_key_ctx key;		/* private key (raw sk bytes) */
	u8 *pub_key;
	u32 pub_key_len;
	u32 param_set;			/* HCQ_SLHDSA_SHAKE_128S .. SHA2_256F */
};

static inline struct cmh_slhdsa_tfm_ctx *cmh_slhdsa_ctx(struct crypto_sig *tfm)
{
	return crypto_sig_ctx(tfm);
}

/*
 * SLH-DSA sign (synchronous sig_alg)
 *
 * @src:  message bytes
 * @slen: message length
 * @dst:  signature output buffer
 * @dlen: output buffer length
 *
 * Returns signature length on success, negative errno on failure.
 * Uses raw private keys written to SYS_REF_TEMP per-operation.
 */
static int cmh_slhdsa_sign(struct crypto_sig *tfm,
			   const void *src, unsigned int slen,
			   void *dst, unsigned int dlen)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);
	u32 sig_sz = slhdsa_get_sig_size(ctx->param_set);
	u32 sk_sz = slhdsa_sk_size(ctx->param_set);
	struct vcq_cmd vcq[HCQ_VCQ_CMDS_MAX]; /* raw: hdr+write+sign+flush */
	u32 vcq_count;
	u8 *m_buf = NULL, *sig_buf = NULL, *sk_buf = NULL;
	dma_addr_t m_dma = DMA_MAPPING_ERROR;
	dma_addr_t sig_dma = DMA_MAPPING_ERROR;
	dma_addr_t sk_dma = DMA_MAPPING_ERROR;
	int ret, idx;

	if (ctx->key.mode == CMH_KEY_NONE)
		return -EINVAL;
	if (dlen < sig_sz)
		return -EINVAL;
	if (!slen || slen > SLHDSA_MAX_MSG_LEN)
		return -EINVAL;

	m_buf = kmemdup(src, slen, GFP_KERNEL);
	sig_buf = kzalloc(sig_sz, GFP_KERNEL);
	if (!m_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	m_dma = cmh_dma_map_single(m_buf, slen, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_buf, sig_sz, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(m_dma) || cmh_dma_map_error(sig_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	sk_dma = DMA_MAPPING_ERROR;
	idx = 0;

	struct core_dispatch d;

	d = cmh_core_select_instance(CMH_CORE_HCQ);

	if (ctx->key.raw.len != sk_sz) {
		ret = -EINVAL;
		goto out_unmap;
	}
	sk_buf = kmemdup(ctx->key.raw.data, ctx->key.raw.len,
			 GFP_KERNEL);
	if (!sk_buf) {
		ret = -ENOMEM;
		goto out_unmap;
	}
	sk_dma = cmh_dma_map_single(sk_buf, sk_sz, DMA_TO_DEVICE);
	if (cmh_dma_map_error(sk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_count = HCQ_VCQ_CMDS_MIN + 1;
	vcq_set_header(&vcq[idx++], vcq_count);
	vcq_add_sys_write(&vcq[idx++], SYS_REF_TEMP, sk_dma,
			  SYS_REF_NONE, sk_sz,
			  ctx->key.raw.sys_type);
	vcq_add_hcq_slhdsa_sign_internal(&vcq[idx++], d.core_id,
					 ctx->param_set,
					 slen, 0,
					 m_dma, SYS_REF_TEMP,
					 sig_dma);
	vcq_add_hcq_flush(&vcq[idx++], d.core_id);

	ret = cmh_tm_submit_sync_tmo(vcq, vcq_count, 1, d.mbx_idx,
				     cmh_tm_slow_op_timeout_jiffies());

	if (!ret) {
		/* Sync bounce buffer so CPU sees the DMA-written signature */
		cmh_dma_sync_for_cpu(sig_dma, sig_sz, DMA_FROM_DEVICE);
		memcpy(dst, sig_buf, sig_sz);
		ret = sig_sz;
	}

out_unmap:
	if (sk_buf) {
		if (!cmh_dma_map_error(sk_dma))
			cmh_dma_unmap_single(sk_dma, sk_sz, DMA_TO_DEVICE);
		kfree_sensitive(sk_buf);
	}
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_sz, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, slen, DMA_TO_DEVICE);

out_free:
	kfree(sig_buf);
	kfree(m_buf);
	return ret;
}

/*
 * SLH-DSA verify (synchronous sig_alg)
 *
 * @src:    raw signature
 * @slen:   signature length
 * @digest: message bytes
 * @dlen:   message length
 *
 * Returns 0 on successful verification, negative errno on failure.
 */
static int cmh_slhdsa_verify(struct crypto_sig *tfm,
			     const void *src, unsigned int slen,
			     const void *digest, unsigned int dlen)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);
	u32 sig_sz = slhdsa_get_sig_size(ctx->param_set);
	u32 pk_sz = slhdsa_pk_size(ctx->param_set);
	struct core_dispatch d = cmh_core_select_instance(CMH_CORE_HCQ);
	struct vcq_cmd vcq[HCQ_VCQ_CMDS_MIN];
	u8 *sig_buf = NULL, *m_buf = NULL, *pk_buf = NULL;
	dma_addr_t sig_dma = DMA_MAPPING_ERROR;
	dma_addr_t m_dma = DMA_MAPPING_ERROR;
	dma_addr_t pk_dma = DMA_MAPPING_ERROR;
	int ret;

	if (!ctx->pub_key)
		return -EINVAL;
	if (slen != sig_sz)
		return -EINVAL;
	if (!dlen || dlen > SLHDSA_MAX_MSG_LEN)
		return -EINVAL;

	sig_buf = kmemdup(src, slen, GFP_KERNEL);
	m_buf = kmemdup(digest, dlen, GFP_KERNEL);
	pk_buf = kmemdup(ctx->pub_key, pk_sz, GFP_KERNEL);
	if (!sig_buf || !m_buf || !pk_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	sig_dma = cmh_dma_map_single(sig_buf, sig_sz, DMA_TO_DEVICE);
	m_dma = cmh_dma_map_single(m_buf, dlen, DMA_TO_DEVICE);
	pk_dma = cmh_dma_map_single(pk_buf, pk_sz, DMA_TO_DEVICE);

	if (cmh_dma_map_error(sig_dma) || cmh_dma_map_error(m_dma) ||
	    cmh_dma_map_error(pk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], HCQ_VCQ_CMDS_MIN);
	vcq_add_hcq_slhdsa_verify_internal(&vcq[1], d.core_id, ctx->param_set,
					   dlen, m_dma, pk_dma, sig_dma);
	vcq_add_hcq_flush(&vcq[2], d.core_id);

	/* SLH-DSA verify recomputes hyper-tree hashes -- inherently slow */
	ret = cmh_tm_submit_sync_tmo(vcq, HCQ_VCQ_CMDS_MIN, 1, d.mbx_idx,
				     cmh_tm_slow_op_timeout_jiffies());

out_unmap:
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, pk_sz, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, dlen, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_sz, DMA_TO_DEVICE);

out_free:
	kfree(pk_buf);
	kfree(m_buf);
	kfree(sig_buf);
	return ret;
}

static int cmh_slhdsa_set_pub_key(struct crypto_sig *tfm,
				  const void *key, unsigned int keylen)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);
	u32 expected = slhdsa_pk_size(ctx->param_set);

	if (keylen != expected)
		return -EINVAL;

	kfree(ctx->pub_key);
	ctx->pub_key = NULL;
	ctx->pub_key_len = 0;

	ctx->pub_key = kmemdup(key, keylen, GFP_KERNEL);
	if (!ctx->pub_key)
		return -ENOMEM;

	ctx->pub_key_len = keylen;
	return 0;
}

static int cmh_slhdsa_set_priv_key(struct crypto_sig *tfm,
				   const void *key, unsigned int keylen)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);

	/* Raw sk (4*n bytes) */
	if (keylen != slhdsa_sk_size(ctx->param_set))
		return -EINVAL;

	return cmh_key_setkey_raw(&ctx->key, key, keylen, CORE_ID_HCQ);
}

static unsigned int cmh_slhdsa_key_size(struct crypto_sig *tfm)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);

	/* crypto_sig_keysize() returns bits, not bytes */
	return slhdsa_pk_size(ctx->param_set) * 8;
}

static unsigned int cmh_slhdsa_max_size(struct crypto_sig *tfm)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);

	return slhdsa_get_sig_size(ctx->param_set);
}

static void cmh_slhdsa_exit(struct crypto_sig *tfm)
{
	struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);

	cmh_key_destroy(&ctx->key);
	kfree(ctx->pub_key);
	ctx->pub_key = NULL;
}

/* Generate init functions for all 12 parameter sets */
#define SLHDSA_INIT(ps_val)						\
	static int cmh_slhdsa_init_##ps_val(struct crypto_sig *tfm)	\
	{								\
		struct cmh_slhdsa_tfm_ctx *ctx = cmh_slhdsa_ctx(tfm);	\
		memset(ctx, 0, sizeof(*ctx));				\
		ctx->param_set = ps_val;				\
		return 0;						\
	}

SLHDSA_INIT(HCQ_SLHDSA_SHAKE_128S)
SLHDSA_INIT(HCQ_SLHDSA_SHAKE_128F)
SLHDSA_INIT(HCQ_SLHDSA_SHAKE_192S)
SLHDSA_INIT(HCQ_SLHDSA_SHAKE_192F)
SLHDSA_INIT(HCQ_SLHDSA_SHAKE_256S)
SLHDSA_INIT(HCQ_SLHDSA_SHAKE_256F)
SLHDSA_INIT(HCQ_SLHDSA_SHA2_128S)
SLHDSA_INIT(HCQ_SLHDSA_SHA2_128F)
SLHDSA_INIT(HCQ_SLHDSA_SHA2_192S)
SLHDSA_INIT(HCQ_SLHDSA_SHA2_192F)
SLHDSA_INIT(HCQ_SLHDSA_SHA2_256S)
SLHDSA_INIT(HCQ_SLHDSA_SHA2_256F)

#define SLHDSA_ALG(name, drv, ps_val) {					\
		.sign		= cmh_slhdsa_sign,			\
		.verify		= cmh_slhdsa_verify,			\
		.set_pub_key	= cmh_slhdsa_set_pub_key,		\
		.set_priv_key	= cmh_slhdsa_set_priv_key,		\
		.key_size	= cmh_slhdsa_key_size,			\
		.max_size	= cmh_slhdsa_max_size,			\
		.init		= cmh_slhdsa_init_##ps_val,		\
		.exit		= cmh_slhdsa_exit,			\
		.base = {						\
			.cra_name	  = name,			\
			.cra_driver_name  = drv,			\
			.cra_priority	  = 300,			\
			.cra_module	  = THIS_MODULE,		\
			.cra_ctxsize	  = sizeof(struct cmh_slhdsa_tfm_ctx), \
		},							\
	}

static struct sig_alg cmh_slhdsa_algs[] = {
	SLHDSA_ALG("slh-dsa-shake-128s", "cri-cmh-slh-dsa-shake-128s", HCQ_SLHDSA_SHAKE_128S),
	SLHDSA_ALG("slh-dsa-shake-128f", "cri-cmh-slh-dsa-shake-128f", HCQ_SLHDSA_SHAKE_128F),
	SLHDSA_ALG("slh-dsa-shake-192s", "cri-cmh-slh-dsa-shake-192s", HCQ_SLHDSA_SHAKE_192S),
	SLHDSA_ALG("slh-dsa-shake-192f", "cri-cmh-slh-dsa-shake-192f", HCQ_SLHDSA_SHAKE_192F),
	SLHDSA_ALG("slh-dsa-shake-256s", "cri-cmh-slh-dsa-shake-256s", HCQ_SLHDSA_SHAKE_256S),
	SLHDSA_ALG("slh-dsa-shake-256f", "cri-cmh-slh-dsa-shake-256f", HCQ_SLHDSA_SHAKE_256F),
	SLHDSA_ALG("slh-dsa-sha2-128s",  "cri-cmh-slh-dsa-sha2-128s",  HCQ_SLHDSA_SHA2_128S),
	SLHDSA_ALG("slh-dsa-sha2-128f",  "cri-cmh-slh-dsa-sha2-128f",  HCQ_SLHDSA_SHA2_128F),
	SLHDSA_ALG("slh-dsa-sha2-192s",  "cri-cmh-slh-dsa-sha2-192s",  HCQ_SLHDSA_SHA2_192S),
	SLHDSA_ALG("slh-dsa-sha2-192f",  "cri-cmh-slh-dsa-sha2-192f",  HCQ_SLHDSA_SHA2_192F),
	SLHDSA_ALG("slh-dsa-sha2-256s",  "cri-cmh-slh-dsa-sha2-256s",  HCQ_SLHDSA_SHA2_256S),
	SLHDSA_ALG("slh-dsa-sha2-256f",  "cri-cmh-slh-dsa-sha2-256f",  HCQ_SLHDSA_SHA2_256F),
};

/**
 * cmh_pqc_slhdsa_register() - Register SLH-DSA akcipher algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_pqc_slhdsa_register(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(cmh_slhdsa_algs); i++) {
		ret = crypto_register_sig(&cmh_slhdsa_algs[i]);
		if (ret) {
			dev_err(cmh_dev(), "cmh: failed to register %s (%d)\n",
				cmh_slhdsa_algs[i].base.cra_name, ret);
			goto err_unregister;
		}
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_sig(&cmh_slhdsa_algs[i]);
	return ret;
}

/**
 * cmh_pqc_slhdsa_unregister() - Unregister SLH-DSA akcipher algorithms from the crypto framework
 */
void cmh_pqc_slhdsa_unregister(void)
{
	int i = ARRAY_SIZE(cmh_slhdsa_algs);

	while (i--)
		crypto_unregister_sig(&cmh_slhdsa_algs[i]);
}
