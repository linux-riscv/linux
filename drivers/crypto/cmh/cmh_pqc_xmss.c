// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- XMSS/XMSS-MT Signature Driver (verify-only, sig_alg, synchronous)
 *
 * Registers "xmss" and "xmss-mt" sig algorithms with verify-only
 * callbacks.  Sign is not supported (stateful signature -- key
 * management must happen externally).
 *
 * Verify: src = raw signature, digest = message bytes
 * Public key: raw pk bytes (variable length, set via set_pub_key)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <crypto/sig.h>
#include <crypto/internal/sig.h>

#include "cmh_sys.h"
#include "cmh_hcq_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_pqc.h"

#define XMSS_VCQ_CMDS	3	/* header + cmd + flush */

struct cmh_xmss_tfm_ctx {
	u8 *pub_key;
	u32 pub_key_len;
	u32 xmss_mt;		/* 0 = XMSS, 1 = XMSS-MT */
};

static inline struct cmh_xmss_tfm_ctx *cmh_xmss_ctx(struct crypto_sig *tfm)
{
	return crypto_sig_ctx(tfm);
}

/*
 * XMSS/XMSS-MT verify (synchronous sig_alg)
 *
 * @src:    raw signature
 * @slen:   signature length
 * @digest: message bytes
 * @dlen:   message length
 *
 * Returns 0 on successful verification, negative errno on failure.
 */
static int cmh_xmss_verify(struct crypto_sig *tfm,
			   const void *src, unsigned int slen,
			   const void *digest, unsigned int dlen)
{
	struct cmh_xmss_tfm_ctx *ctx = cmh_xmss_ctx(tfm);
	struct core_dispatch d = cmh_core_select_instance(CMH_CORE_HCQ);
	struct vcq_cmd vcq[XMSS_VCQ_CMDS];
	u8 *sig_buf = NULL, *m_buf = NULL, *pk_buf = NULL;
	dma_addr_t sig_dma = DMA_MAPPING_ERROR;
	dma_addr_t m_dma = DMA_MAPPING_ERROR;
	dma_addr_t pk_dma = DMA_MAPPING_ERROR;
	int ret;

	if (!ctx->pub_key)
		return -EINVAL;
	if (!slen || slen > XMSS_MAX_SIG_LEN)
		return -EINVAL;
	if (!dlen || dlen > XMSS_MAX_MSG_LEN)
		return -EINVAL;

	sig_buf = kmemdup(src, slen, GFP_KERNEL);
	m_buf = kmemdup(digest, dlen, GFP_KERNEL);
	pk_buf = kmemdup(ctx->pub_key, ctx->pub_key_len, GFP_KERNEL);
	if (!sig_buf || !m_buf || !pk_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	sig_dma = cmh_dma_map_single(sig_buf, slen, DMA_TO_DEVICE);
	m_dma = cmh_dma_map_single(m_buf, dlen, DMA_TO_DEVICE);
	pk_dma = cmh_dma_map_single(pk_buf, ctx->pub_key_len, DMA_TO_DEVICE);

	if (cmh_dma_map_error(sig_dma) || cmh_dma_map_error(m_dma) ||
	    cmh_dma_map_error(pk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], XMSS_VCQ_CMDS);
	vcq_add_hcq_xmss_verify(&vcq[1], d.core_id, ctx->xmss_mt,
				ctx->pub_key_len, slen, dlen,
				pk_dma, sig_dma, m_dma);
	vcq_add_hcq_flush(&vcq[2], d.core_id);

	/* XMSS verify traverses Merkle hash chains -- inherently slow */
	ret = cmh_tm_submit_sync_tmo(vcq, XMSS_VCQ_CMDS, 1, d.mbx_idx,
				     cmh_tm_slow_op_timeout_jiffies());

out_unmap:
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, ctx->pub_key_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(m_dma))
		cmh_dma_unmap_single(m_dma, dlen, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, slen, DMA_TO_DEVICE);

out_free:
	kfree(pk_buf);
	kfree(m_buf);
	kfree(sig_buf);
	return ret;
}

static int cmh_xmss_set_pub_key(struct crypto_sig *tfm,
				const void *key, unsigned int keylen)
{
	struct cmh_xmss_tfm_ctx *ctx = cmh_xmss_ctx(tfm);

	if (!keylen || keylen > XMSS_MAX_PK_LEN)
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

static unsigned int cmh_xmss_key_size(struct crypto_sig *tfm)
{
	struct cmh_xmss_tfm_ctx *ctx = cmh_xmss_ctx(tfm);

	return ctx->pub_key_len * 8;
}

static int cmh_xmss_init(struct crypto_sig *tfm)
{
	struct cmh_xmss_tfm_ctx *ctx = cmh_xmss_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

static int cmh_xmss_mt_init(struct crypto_sig *tfm)
{
	struct cmh_xmss_tfm_ctx *ctx = cmh_xmss_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->xmss_mt = 1;
	return 0;
}

static void cmh_xmss_exit(struct crypto_sig *tfm)
{
	struct cmh_xmss_tfm_ctx *ctx = cmh_xmss_ctx(tfm);

	kfree(ctx->pub_key);
	ctx->pub_key = NULL;
}

static struct sig_alg cmh_xmss_algs[] = {
	{
		.verify		= cmh_xmss_verify,
		.set_pub_key	= cmh_xmss_set_pub_key,
		.key_size	= cmh_xmss_key_size,
		.init		= cmh_xmss_init,
		.exit		= cmh_xmss_exit,
		.base = {
			.cra_name	  = "xmss",
			.cra_driver_name  = "cri-cmh-xmss",
			.cra_priority	  = 300,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_xmss_tfm_ctx),
		},
	},
	{
		.verify		= cmh_xmss_verify,
		.set_pub_key	= cmh_xmss_set_pub_key,
		.key_size	= cmh_xmss_key_size,
		.init		= cmh_xmss_mt_init,
		.exit		= cmh_xmss_exit,
		.base = {
			.cra_name	  = "xmss-mt",
			.cra_driver_name  = "cri-cmh-xmss-mt",
			.cra_priority	  = 300,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_xmss_tfm_ctx),
		},
	},
};

/**
 * cmh_pqc_xmss_register() - Register XMSS/XMSS-MT sig algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_pqc_xmss_register(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(cmh_xmss_algs); i++) {
		ret = crypto_register_sig(&cmh_xmss_algs[i]);
		if (ret) {
			dev_err(cmh_dev(), "cmh: failed to register %s (%d)\n",
				cmh_xmss_algs[i].base.cra_name, ret);
			goto err_unregister;
		}
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_sig(&cmh_xmss_algs[i]);
	return ret;
}

/**
 * cmh_pqc_xmss_unregister() - Unregister XMSS/XMSS-MT sig algorithms from the crypto framework
 */
void cmh_pqc_xmss_unregister(void)
{
	int i = ARRAY_SIZE(cmh_xmss_algs);

	while (i--)
		crypto_unregister_sig(&cmh_xmss_algs[i]);
}
