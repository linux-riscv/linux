// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- ML-DSA Signature Driver (sig_alg, synchronous)
 *
 * Registers "mldsa44", "mldsa65", "mldsa87" sig algorithms
 * with sign, verify, set_pub_key, and set_priv_key callbacks.
 *
 * Key format:
 *   Public key  = raw pk bytes (1312 / 1952 / 2592 bytes)
 *   Private key = raw sk bytes (2560 / 4032 / 4896 bytes)
 *
 * Sign: src = message bytes (up to 10240 bytes), dst = raw signature
 * Verify: src = raw signature, digest = message bytes
 *
 * Non-masked mode only for sig_alg API.
 * Masked mode available through /dev/cmh_mgmt ioctl.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <crypto/sig.h>
#include <crypto/internal/sig.h>

#include "cmh_sys.h"
#include "cmh_qse_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"
#include "cmh_pqc.h"

struct cmh_mldsa_tfm_ctx {
	struct cmh_key_ctx key;		/* private key (raw only) */
	u8 *pub_key;
	u32 pub_key_len;
	u32 mode;			/* ML_DSA_MODE_44/65/87 */
	int mode_idx;			/* index into size tables */
};

static inline struct cmh_mldsa_tfm_ctx *cmh_mldsa_ctx(struct crypto_sig *tfm)
{
	return crypto_sig_ctx(tfm);
}

/*
 * ML-DSA sign (synchronous sig_alg)
 *
 * @src:  message bytes
 * @slen: message length
 * @dst:  signature output buffer
 * @dlen: output buffer length
 *
 * Returns signature length on success, negative errno on failure.
 */
static int cmh_mldsa_sign(struct crypto_sig *tfm,
			  const void *src, unsigned int slen,
			  void *dst, unsigned int dlen)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);
	int mi = ctx->mode_idx;
	u32 sig_size = ml_dsa_sig_size[mi];
	u32 sk_size = ml_dsa_sk_size[mi];
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MIN];
	struct core_dispatch dd;
	u8 *m_buf = NULL, *sig_buf = NULL, *sk_buf = NULL;
	dma_addr_t m_dma = DMA_MAPPING_ERROR;
	dma_addr_t sig_dma = DMA_MAPPING_ERROR;
	dma_addr_t sk_dma = DMA_MAPPING_ERROR;
	int ret, idx;

	if (ctx->key.mode != CMH_KEY_RAW)
		return -EINVAL;
	if (dlen < sig_size)
		return -EINVAL;
	if (!slen || slen > ML_DSA_MAX_MLEN)
		return -EINVAL;

	m_buf = kmemdup(src, slen, GFP_KERNEL);
	sig_buf = kzalloc(sig_size, GFP_KERNEL);
	if (!m_buf || !sig_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (ctx->key.raw.len != sk_size) {
		ret = -EINVAL;
		goto out_free;
	}

	sk_buf = kmemdup(ctx->key.raw.data, ctx->key.raw.len, GFP_KERNEL);
	if (!sk_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	m_dma = cmh_dma_map_single(m_buf, slen, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_buf, sig_size, DMA_FROM_DEVICE);
	sk_dma = cmh_dma_map_single(sk_buf, sk_size, DMA_TO_DEVICE);

	if (cmh_dma_map_error(m_dma) || cmh_dma_map_error(sig_dma) ||
	    cmh_dma_map_error(sk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	dd = cmh_core_select_instance(CMH_CORE_QSE);

	vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
	idx = 1;
	vcq_add_qse_ml_dsa_sign(&vcq[idx++], dd.core_id, ctx->mode,
				QSE_FLAG_USE_RNG,
				0, m_dma, sk_dma, sig_dma, slen, false);
	vcq_add_qse_flush(&vcq[idx++], dd.core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN, 1,
				     dd.mbx_idx);
	if (!ret) {
		/* Sync bounce buffer so CPU sees the DMA-written signature */
		cmh_dma_sync_for_cpu(sig_dma, sig_size, DMA_FROM_DEVICE);
		memcpy(dst, sig_buf, sig_size);
		ret = sig_size;
	}

out_unmap:
	if (!cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, sk_size, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_size, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, slen, DMA_TO_DEVICE);

out_free:
	kfree_sensitive(sk_buf);
	kfree(sig_buf);
	kfree(m_buf);
	return ret;
}

/*
 * ML-DSA verify (synchronous sig_alg)
 *
 * @src:    raw signature
 * @slen:   signature length
 * @digest: message bytes
 * @dlen:   message length
 *
 * Returns 0 on successful verification, negative errno on failure.
 */
static int cmh_mldsa_verify(struct crypto_sig *tfm,
			    const void *src, unsigned int slen,
			    const void *digest, unsigned int dlen)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);
	int mi = ctx->mode_idx;
	u32 sig_size = ml_dsa_sig_size[mi];
	u32 pk_size = ml_dsa_pk_size[mi];
	struct core_dispatch d = cmh_core_select_instance(CMH_CORE_QSE);
	struct vcq_cmd vcq[QSE_VCQ_CMDS_MIN];
	u8 *sig_buf = NULL, *m_buf = NULL, *pk_buf = NULL;
	dma_addr_t sig_dma = DMA_MAPPING_ERROR;
	dma_addr_t m_dma = DMA_MAPPING_ERROR;
	dma_addr_t pk_dma = DMA_MAPPING_ERROR;
	int ret;

	if (!ctx->pub_key)
		return -EINVAL;
	if (slen != sig_size)
		return -EINVAL;
	if (!dlen || dlen > ML_DSA_MAX_MLEN)
		return -EINVAL;

	sig_buf = kmemdup(src, slen, GFP_KERNEL);
	m_buf = kmemdup(digest, dlen, GFP_KERNEL);
	pk_buf = kmemdup(ctx->pub_key, pk_size, GFP_KERNEL);
	if (!sig_buf || !m_buf || !pk_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	sig_dma = cmh_dma_map_single(sig_buf, sig_size, DMA_TO_DEVICE);
	m_dma = cmh_dma_map_single(m_buf, dlen, DMA_TO_DEVICE);
	pk_dma = cmh_dma_map_single(pk_buf, pk_size, DMA_TO_DEVICE);

	if (cmh_dma_map_error(sig_dma) || cmh_dma_map_error(m_dma) ||
	    cmh_dma_map_error(pk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], QSE_VCQ_CMDS_MIN);
	vcq_add_qse_ml_dsa_verify(&vcq[1], d.core_id, ctx->mode, 0,
				  m_dma, pk_dma, sig_dma, dlen);
	vcq_add_qse_flush(&vcq[2], d.core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, QSE_VCQ_CMDS_MIN, 1, d.mbx_idx);

out_unmap:
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, pk_size, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, dlen, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_size, DMA_TO_DEVICE);

out_free:
	kfree(pk_buf);
	kfree(m_buf);
	kfree(sig_buf);
	return ret;
}

static int cmh_mldsa_set_pub_key(struct crypto_sig *tfm,
				 const void *key, unsigned int keylen)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);
	u32 expected = ml_dsa_pk_size[ctx->mode_idx];

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

static int cmh_mldsa_set_priv_key(struct crypto_sig *tfm,
				  const void *key, unsigned int keylen)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);
	u32 expected = ml_dsa_sk_size[ctx->mode_idx];

	if (keylen != expected)
		return -EINVAL;

	return cmh_key_setkey_raw(&ctx->key, key, keylen, CORE_ID_QSE);
}

static unsigned int cmh_mldsa_key_size(struct crypto_sig *tfm)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);

	/* crypto_sig_keysize() returns bits, not bytes */
	return ml_dsa_pk_size[ctx->mode_idx] * 8;
}

static unsigned int cmh_mldsa_max_size(struct crypto_sig *tfm)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);

	return ml_dsa_sig_size[ctx->mode_idx];
}

static int cmh_mldsa_44_init(struct crypto_sig *tfm)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->mode = ML_DSA_MODE_44;
	ctx->mode_idx = 0;
	return 0;
}

static int cmh_mldsa_65_init(struct crypto_sig *tfm)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->mode = ML_DSA_MODE_65;
	ctx->mode_idx = 1;
	return 0;
}

static int cmh_mldsa_87_init(struct crypto_sig *tfm)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->mode = ML_DSA_MODE_87;
	ctx->mode_idx = 2;
	return 0;
}

static void cmh_mldsa_exit(struct crypto_sig *tfm)
{
	struct cmh_mldsa_tfm_ctx *ctx = cmh_mldsa_ctx(tfm);

	cmh_key_destroy(&ctx->key);
	kfree(ctx->pub_key);
	ctx->pub_key = NULL;
}

/*
 * Priority 5001: the kernel's software ML-DSA (crypto/mldsa.c) registers
 * at priority 5000 but only implements verify -- sign returns -EOPNOTSUPP.
 * We provide full HW-accelerated sign + verify, so we must override.
 */
static struct sig_alg cmh_mldsa_algs[] = {
	{
		.sign		= cmh_mldsa_sign,
		.verify		= cmh_mldsa_verify,
		.set_pub_key	= cmh_mldsa_set_pub_key,
		.set_priv_key	= cmh_mldsa_set_priv_key,
		.key_size	= cmh_mldsa_key_size,
		.max_size	= cmh_mldsa_max_size,
		.init		= cmh_mldsa_44_init,
		.exit		= cmh_mldsa_exit,
		.base = {
			.cra_name	  = "mldsa44",
			.cra_driver_name  = "cri-cmh-mldsa44",
			.cra_priority	  = 5001,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_mldsa_tfm_ctx),
		},
	},
	{
		.sign		= cmh_mldsa_sign,
		.verify		= cmh_mldsa_verify,
		.set_pub_key	= cmh_mldsa_set_pub_key,
		.set_priv_key	= cmh_mldsa_set_priv_key,
		.key_size	= cmh_mldsa_key_size,
		.max_size	= cmh_mldsa_max_size,
		.init		= cmh_mldsa_65_init,
		.exit		= cmh_mldsa_exit,
		.base = {
			.cra_name	  = "mldsa65",
			.cra_driver_name  = "cri-cmh-mldsa65",
			.cra_priority	  = 5001,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_mldsa_tfm_ctx),
		},
	},
	{
		.sign		= cmh_mldsa_sign,
		.verify		= cmh_mldsa_verify,
		.set_pub_key	= cmh_mldsa_set_pub_key,
		.set_priv_key	= cmh_mldsa_set_priv_key,
		.key_size	= cmh_mldsa_key_size,
		.max_size	= cmh_mldsa_max_size,
		.init		= cmh_mldsa_87_init,
		.exit		= cmh_mldsa_exit,
		.base = {
			.cra_name	  = "mldsa87",
			.cra_driver_name  = "cri-cmh-mldsa87",
			.cra_priority	  = 5001,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_mldsa_tfm_ctx),
		},
	},
};

/**
 * cmh_pqc_mldsa_register() - Register ML-DSA akcipher algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_pqc_mldsa_register(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(cmh_mldsa_algs); i++) {
		ret = crypto_register_sig(&cmh_mldsa_algs[i]);
		if (ret) {
			dev_err(cmh_dev(), "cmh: failed to register %s (%d)\n",
				cmh_mldsa_algs[i].base.cra_name, ret);
			goto err_unregister;
		}
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_sig(&cmh_mldsa_algs[i]);
	return ret;
}

/**
 * cmh_pqc_mldsa_unregister() - Unregister ML-DSA akcipher algorithms from the crypto framework
 */
void cmh_pqc_mldsa_unregister(void)
{
	int i = ARRAY_SIZE(cmh_mldsa_algs);

	while (i--)
		crypto_unregister_sig(&cmh_mldsa_algs[i]);
}
