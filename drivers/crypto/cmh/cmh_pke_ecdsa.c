// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- ECDSA / SM2 Signature Driver (sig_alg, synchronous)
 *
 * Registers "ecdsa-nist-p256", "ecdsa-nist-p384", and "ecdsa-nist-p521"
 * sig algorithms with sign, verify, set_pub_key, and set_priv_key callbacks.
 * Registers "sm2" as verify-only (set_pub_key + verify); SM2 sign is
 * provided via the cmh_mgmt ioctl path in cmh_pke_sm2.c.
 *
 * In-kernel consumers typically use verify-only (module signatures, IMA),
 * but we provide sign as well for completeness -- matching the CMH eSW
 * capability.
 *
 * Key format: Public key = raw 04 || X || Y (uncompressed).
 * Signature format: struct ecdsa_raw_sig (two u64[ECC_MAX_DIGITS] arrays
 * in VLI format -- native byte order, LE digit order) for both sign
 * output and verify input.  This matches the kernel crypto sig API.
 *
 * Private key via cmh_key_ctx: raw keys written via SYS_REF_TEMP.
 * Datastore-referenced keys are only reachable through the ioctl
 * path (cmh_mgmt.c).
 *
 * SM2 note: The SM2 sig entry is verify-only (no sign/set_priv_key).
 * SM2 signature verification requires the digest to be SM3(ZA || M)
 * where ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA).
 * The ZA identity pre-hash is the caller's responsibility; the driver
 * passes the digest directly to the CMH eSW SM2 verify engine.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <crypto/sha2.h>
#include <crypto/sig.h>
#include <crypto/internal/sig.h>
#include <crypto/internal/ecc.h>

#include "cmh_pke.h"
#include "cmh_sys.h"
#include "cmh_sys_abi.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_key.h"

/*
 * Number of ECC digits needed for a given coordinate byte length.
 * P-256: 4, P-384: 6, P-521/SM2(clen=68): 9.
 */
static inline unsigned int clen_to_ndigits(u32 clen)
{
	return DIV_ROUND_UP(clen, sizeof(u64));
}

struct cmh_ecdsa_tfm_ctx {
	struct cmh_key_ctx key;		/* private key (raw only) */
	u8 *pub_key;			/* uncompressed (x, y) without 04 prefix */
	u32 pub_key_len;
	u32 curve;			/* PKE_CURVE_* */
	u32 clen;			/* coordinate length in bytes */
};

static inline struct cmh_ecdsa_tfm_ctx *cmh_ecdsa_ctx(struct crypto_sig *tfm)
{
	return crypto_sig_ctx(tfm);
}

/*
 * Convert one VLI component (u64 array, LE digit order, native byte order)
 * to big-endian byte array of @out_len bytes.  The VLI value is right-aligned
 * in the output (leading zero bytes if ndigits*8 > out_len are discarded;
 * leading zero padding added if ndigits*8 < out_len).
 */
static void ecdsa_vli_to_be(const u64 *vli, unsigned int ndigits,
			    u8 *out, unsigned int out_len)
{
	unsigned int full_len = ndigits * sizeof(u64);
	unsigned int i, skip;

	memset(out, 0, out_len);

	if (full_len <= out_len) {
		/* VLI fits entirely -- write at right end of out */
		u8 *dst = out + (out_len - full_len);

		for (i = 0; i < ndigits; i++)
			put_unaligned_be64(vli[ndigits - 1 - i],
					   &dst[i * sizeof(u64)]);
	} else {
		/* VLI wider than out -- skip leading (zero) bytes */
		u8 tmp[ECC_MAX_BYTES];

		for (i = 0; i < ndigits; i++)
			put_unaligned_be64(vli[ndigits - 1 - i],
					   &tmp[i * sizeof(u64)]);
		skip = full_len - out_len;
		WARN_ON_ONCE(memchr_inv(tmp, 0, skip));
		memcpy(out, tmp + skip, out_len);
	}
}

/*
 * Convert big-endian byte array to VLI (u64 array, LE digit order).
 * Output is zero-filled to @max_digits entries.
 */
static void ecdsa_be_to_vli(const u8 *in, unsigned int in_len,
			    u64 *vli, unsigned int max_digits)
{
	unsigned int full_len = max_digits * sizeof(u64);
	u8 tmp[ECC_MAX_BYTES];
	unsigned int i;

	if (WARN_ON_ONCE(max_digits > ECC_MAX_DIGITS))
		max_digits = ECC_MAX_DIGITS;

	memset(tmp, 0, full_len);
	if (in_len <= full_len)
		memcpy(tmp + (full_len - in_len), in, in_len);
	else
		memcpy(tmp, in + (in_len - full_len), full_len);

	for (i = 0; i < max_digits; i++) {
		unsigned int off = (max_digits - 1 - i) * sizeof(u64);

		vli[i] = get_unaligned_be64(&tmp[off]);
	}
}

/*
 * Extract raw (r || s) big-endian byte arrays from struct ecdsa_raw_sig.
 * Each component is written as @clen bytes into @raw_rs.
 */
static int ecdsa_sig_to_raw(const void *src, unsigned int slen,
			    u8 *raw_rs, u32 clen)
{
	const struct ecdsa_raw_sig *sig = src;
	unsigned int ndigits = clen_to_ndigits(clen);

	if (slen != sizeof(struct ecdsa_raw_sig))
		return -EINVAL;

	ecdsa_vli_to_be(sig->r, ndigits, raw_rs, clen);
	ecdsa_vli_to_be(sig->s, ndigits, raw_rs + clen, clen);
	return 0;
}

/*
 * Encode raw (r || s) big-endian byte arrays into struct ecdsa_raw_sig.
 * Returns sizeof(struct ecdsa_raw_sig) on success.
 */
static int ecdsa_raw_to_sig(const u8 *raw_rs, u32 clen,
			    void *dst, unsigned int dlen)
{
	struct ecdsa_raw_sig *sig = dst;

	if (dlen < sizeof(struct ecdsa_raw_sig))
		return -ENOSPC;

	memset(sig, 0, sizeof(*sig));
	ecdsa_be_to_vli(raw_rs, clen, sig->r, ECC_MAX_DIGITS);
	ecdsa_be_to_vli(raw_rs + clen, clen, sig->s, ECC_MAX_DIGITS);
	return sizeof(struct ecdsa_raw_sig);
}

/*
 * ECDSA verify (synchronous sig_alg)
 *
 * @src:    struct ecdsa_raw_sig (VLI format)
 * @slen:   signature length (must be sizeof(struct ecdsa_raw_sig))
 * @digest: hash digest
 * @dlen:   digest length
 *
 * Returns 0 on successful verification, negative errno on failure.
 */
static int cmh_ecdsa_verify(struct crypto_sig *tfm,
			    const void *src, unsigned int slen,
			    const void *digest, unsigned int dlen)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);
	u32 clen = ctx->clen;
	u32 sig_raw_len = 2 * clen;
	u32 copy_len = min_t(u32, dlen, clen);
	struct core_dispatch d = cmh_core_select_instance(CMH_CORE_PKE);
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MIN];
	u8 *sig_raw = NULL, *dig_buf = NULL, *pk_buf = NULL, *rp_buf = NULL;
	dma_addr_t pk_dma, dig_dma, sig_dma, rp_dma;
	int ret;

	if (!ctx->pub_key)
		return -EINVAL;

	sig_raw = kzalloc(sig_raw_len, GFP_KERNEL);
	dig_buf = kzalloc(clen, GFP_KERNEL);
	pk_buf = kmemdup(ctx->pub_key, ctx->pub_key_len, GFP_KERNEL);
	rp_buf = kzalloc(clen, GFP_KERNEL);
	if (!sig_raw || !dig_buf || !pk_buf || !rp_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	/* Extract raw (r, s) big-endian from VLI signature */
	ret = ecdsa_sig_to_raw(src, slen, sig_raw, clen);
	if (ret)
		goto out_free;

	/*
	 * Truncate or zero-pad digest to clen bytes, right-aligned.
	 * Matches ECDSA bits2int: use leftmost min(dlen, clen) bytes,
	 * zero-pad on the left when dlen < clen.
	 */
	memcpy(dig_buf + (clen - copy_len), digest, copy_len);

	pk_dma = cmh_dma_map_single(pk_buf, ctx->pub_key_len, DMA_TO_DEVICE);
	dig_dma = cmh_dma_map_single(dig_buf, clen, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_raw, sig_raw_len, DMA_TO_DEVICE);
	rp_dma = cmh_dma_map_single(rp_buf, clen, DMA_FROM_DEVICE);

	if (cmh_dma_map_error(pk_dma) || cmh_dma_map_error(dig_dma) ||
	    cmh_dma_map_error(sig_dma) || cmh_dma_map_error(rp_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	vcq_set_header(&vcq[0], PKE_VCQ_CMDS_MIN);
	vcq_add_pke_ecdsa_verify(&vcq[1], d.core_id, ctx->curve, clen,
				 pk_dma, dig_dma, sig_dma, rp_dma,
				 pke_swap_flags(ctx->curve));
	vcq_add_pke_flush(&vcq[2], d.core_id);

	ret = cmh_tm_submit_sync_mbx(vcq, PKE_VCQ_CMDS_MIN, 1, d.mbx_idx);

out_unmap:
	if (!cmh_dma_map_error(rp_dma))
		cmh_dma_unmap_single(rp_dma, clen, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_raw_len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(dig_dma))
		cmh_dma_unmap_single(dig_dma, clen, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(pk_dma))
		cmh_dma_unmap_single(pk_dma, ctx->pub_key_len, DMA_TO_DEVICE);

out_free:
	kfree(rp_buf);
	kfree(pk_buf);
	kfree(sig_raw);
	kfree(dig_buf);
	return ret;
}

/*
 * ECDSA sign (synchronous sig_alg)
 *
 * @src:  hash digest
 * @slen: digest length
 * @dst:  output buffer for struct ecdsa_raw_sig (VLI format)
 * @dlen: output buffer length
 *
 * Returns sizeof(struct ecdsa_raw_sig) on success, negative errno on failure.
 */
static int cmh_ecdsa_sign(struct crypto_sig *tfm,
			  const void *src, unsigned int slen,
			  void *dst, unsigned int dlen)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);
	u32 clen = ctx->clen;
	u32 sig_raw_len = 2 * clen;
	u32 copy_len = min_t(u32, slen, clen);
	struct core_dispatch dd;
	struct vcq_cmd vcq[PKE_VCQ_CMDS_MAX];
	u8 *dig_buf = NULL, *sig_buf = NULL, *sk_buf = NULL;
	dma_addr_t dig_dma, sig_dma, sk_dma;
	int ret, idx;

	if (ctx->key.mode != CMH_KEY_RAW)
		return -EINVAL;
	if (dlen < sizeof(struct ecdsa_raw_sig))
		return -EINVAL;

	dig_buf = kzalloc(clen, GFP_KERNEL);
	sig_buf = kzalloc(sig_raw_len, GFP_KERNEL);
	sk_buf = kmemdup(ctx->key.raw.data, ctx->key.raw.len, GFP_KERNEL);
	if (!dig_buf || !sig_buf || !sk_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	/*
	 * Truncate or zero-pad digest to clen bytes, right-aligned.
	 * Matches ECDSA bits2int: use leftmost min(slen, clen) bytes,
	 * zero-pad on the left when slen < clen.
	 */
	memcpy(dig_buf + (clen - copy_len), src, copy_len);

	dig_dma = cmh_dma_map_single(dig_buf, clen, DMA_TO_DEVICE);
	sig_dma = cmh_dma_map_single(sig_buf, sig_raw_len, DMA_FROM_DEVICE);
	sk_dma = cmh_dma_map_single(sk_buf, ctx->key.raw.len, DMA_TO_DEVICE);

	if (cmh_dma_map_error(dig_dma) || cmh_dma_map_error(sig_dma) ||
	    cmh_dma_map_error(sk_dma)) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	dd = cmh_core_select_instance(CMH_CORE_PKE);

	idx = 1;
	vcq_add_sys_write(&vcq[idx], SYS_REF_TEMP, sk_dma,
			  SYS_REF_NONE, ctx->key.raw.len,
			  ctx->key.raw.sys_type);
	vcq[idx].id |= pke_swap_flags(ctx->curve);
	idx++;
	vcq_add_pke_ecdsa_sign(&vcq[idx++], dd.core_id, ctx->curve, clen,
			       dig_dma, sig_dma, SYS_REF_TEMP,
			       clen, pke_swap_flags(ctx->curve));
	vcq_add_pke_flush(&vcq[idx++], dd.core_id);
	vcq_set_header(&vcq[0], idx);

	ret = cmh_tm_submit_sync_mbx(vcq, idx, 1, dd.mbx_idx);
	if (!ret) {
		/* Sync bounce buffer so CPU sees the DMA-written signature */
		cmh_dma_sync_for_cpu(sig_dma, sig_raw_len, DMA_FROM_DEVICE);

		/* Encode raw (r||s) into VLI ecdsa_raw_sig for kernel API */
		ret = ecdsa_raw_to_sig(sig_buf, clen, dst, dlen);
	}

out_unmap:
	if (!cmh_dma_map_error(sk_dma))
		cmh_dma_unmap_single(sk_dma, ctx->key.raw.len, DMA_TO_DEVICE);
	if (!cmh_dma_map_error(sig_dma))
		cmh_dma_unmap_single(sig_dma, sig_raw_len, DMA_FROM_DEVICE);
	if (!cmh_dma_map_error(dig_dma))
		cmh_dma_unmap_single(dig_dma, clen, DMA_TO_DEVICE);

out_free:
	kfree_sensitive(sk_buf);
	kfree(sig_buf);
	kfree(dig_buf);
	return ret;
}

static int cmh_ecdsa_set_pub_key(struct crypto_sig *tfm,
				 const void *key, unsigned int keylen)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);
	const u8 *d = key;
	u32 clen = ctx->clen;
	u32 raw_clen;

	/* Accept 04 || X || Y (uncompressed point) */
	if (keylen < 1 || d[0] != 0x04)
		return -EINVAL;
	d++;
	keylen--;

	if (keylen & 1)
		return -EINVAL;
	raw_clen = keylen / 2;

	/*
	 * Kernel passes ceil(bits/8) per coordinate (e.g. 66 for P-521),
	 * but our HW ABI uses clen (ALIGN(66,4)=68 for P-521).
	 * Accept raw_clen <= clen and zero-pad on the left.
	 */
	if (raw_clen > clen || raw_clen == 0)
		return -EINVAL;

	kfree(ctx->pub_key);
	ctx->pub_key = NULL;
	ctx->pub_key_len = 0;

	ctx->pub_key = kzalloc(2 * clen, GFP_KERNEL);
	if (!ctx->pub_key)
		return -ENOMEM;

	/* Right-align each coordinate to clen bytes */
	memcpy(ctx->pub_key + (clen - raw_clen), d, raw_clen);
	memcpy(ctx->pub_key + clen + (clen - raw_clen), d + raw_clen,
	       raw_clen);
	ctx->pub_key_len = 2 * clen;
	return 0;
}

static int cmh_ecdsa_set_priv_key(struct crypto_sig *tfm,
				  const void *key, unsigned int keylen)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	if (keylen != ctx->clen)
		return -EINVAL;

	return cmh_key_setkey_raw(&ctx->key, key, keylen, CORE_ID_PKE);
}

static unsigned int cmh_ecdsa_key_size(struct crypto_sig *tfm)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	/* crypto_sig_keysize() returns bits, not bytes */
	return pke_curve_bits(ctx->curve);
}

static unsigned int cmh_ecdsa_max_size(struct crypto_sig *tfm)
{
	return sizeof(struct ecdsa_raw_sig);
}

static unsigned int cmh_ecdsa_digest_size(struct crypto_sig *tfm)
{
	/*
	 * Accept digests up to SHA-512 (64 bytes).  Digests longer
	 * than the curve order are truncated per ECDSA bits2int.
	 * Matches kernel ecdsa_digest_size().
	 */
	return SHA512_DIGEST_SIZE;
}

static int cmh_ecdsa_p256_init(struct crypto_sig *tfm)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_P256;
	ctx->clen = pke_curve_clen(PKE_CURVE_P256);
	return 0;
}

static int cmh_ecdsa_p384_init(struct crypto_sig *tfm)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_P384;
	ctx->clen = pke_curve_clen(PKE_CURVE_P384);
	return 0;
}

static int cmh_ecdsa_p521_init(struct crypto_sig *tfm)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_P521;
	ctx->clen = pke_curve_clen(PKE_CURVE_P521);
	return 0;
}

static int cmh_sm2_init(struct crypto_sig *tfm)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->curve = PKE_CURVE_SM2;
	ctx->clen = pke_curve_clen(PKE_CURVE_SM2);
	return 0;
}

static void cmh_ecdsa_exit(struct crypto_sig *tfm)
{
	struct cmh_ecdsa_tfm_ctx *ctx = cmh_ecdsa_ctx(tfm);

	cmh_key_destroy(&ctx->key);
	kfree(ctx->pub_key);
	ctx->pub_key = NULL;
}

static struct sig_alg cmh_ecdsa_algs[] = {
	{
		.sign		= cmh_ecdsa_sign,
		.verify		= cmh_ecdsa_verify,
		.set_pub_key	= cmh_ecdsa_set_pub_key,
		.set_priv_key	= cmh_ecdsa_set_priv_key,
		.key_size	= cmh_ecdsa_key_size,
		.max_size	= cmh_ecdsa_max_size,
		.digest_size	= cmh_ecdsa_digest_size,
		.init		= cmh_ecdsa_p256_init,
		.exit		= cmh_ecdsa_exit,
		.base = {
			.cra_name	  = "ecdsa-nist-p256",
			.cra_driver_name  = "cri-cmh-ecdsa-nist-p256",
			.cra_priority	  = 300,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdsa_tfm_ctx),
		},
	},
	{
		.sign		= cmh_ecdsa_sign,
		.verify		= cmh_ecdsa_verify,
		.set_pub_key	= cmh_ecdsa_set_pub_key,
		.set_priv_key	= cmh_ecdsa_set_priv_key,
		.key_size	= cmh_ecdsa_key_size,
		.max_size	= cmh_ecdsa_max_size,
		.digest_size	= cmh_ecdsa_digest_size,
		.init		= cmh_ecdsa_p384_init,
		.exit		= cmh_ecdsa_exit,
		.base = {
			.cra_name	  = "ecdsa-nist-p384",
			.cra_driver_name  = "cri-cmh-ecdsa-nist-p384",
			.cra_priority	  = 300,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdsa_tfm_ctx),
		},
	},
	{
		.sign		= cmh_ecdsa_sign,
		.verify		= cmh_ecdsa_verify,
		.set_pub_key	= cmh_ecdsa_set_pub_key,
		.set_priv_key	= cmh_ecdsa_set_priv_key,
		.key_size	= cmh_ecdsa_key_size,
		.max_size	= cmh_ecdsa_max_size,
		.digest_size	= cmh_ecdsa_digest_size,
		.init		= cmh_ecdsa_p521_init,
		.exit		= cmh_ecdsa_exit,
		.base = {
			.cra_name	  = "ecdsa-nist-p521",
			.cra_driver_name  = "cri-cmh-ecdsa-nist-p521",
			.cra_priority	  = 300,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdsa_tfm_ctx),
		},
	},
	{
		.verify		= cmh_ecdsa_verify,
		.set_pub_key	= cmh_ecdsa_set_pub_key,
		.key_size	= cmh_ecdsa_key_size,
		.max_size	= cmh_ecdsa_max_size,
		.digest_size	= cmh_ecdsa_digest_size,
		.init		= cmh_sm2_init,
		.exit		= cmh_ecdsa_exit,
		.base = {
			.cra_name	  = "sm2",
			.cra_driver_name  = "cri-cmh-sm2",
			.cra_priority	  = 300,
			.cra_module	  = THIS_MODULE,
			.cra_ctxsize	  = sizeof(struct cmh_ecdsa_tfm_ctx),
		},
	},
};

/**
 * cmh_pke_ecdsa_register() - Register ECDSA/SM2 sig algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_pke_ecdsa_register(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(cmh_ecdsa_algs); i++) {
		ret = crypto_register_sig(&cmh_ecdsa_algs[i]);
		if (ret) {
			dev_err(cmh_dev(), "cmh: failed to register %s (%d)\n",
				cmh_ecdsa_algs[i].base.cra_name, ret);
			goto err_unregister;
		}
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_sig(&cmh_ecdsa_algs[i]);
	return ret;
}

/**
 * cmh_pke_ecdsa_unregister() - Unregister ECDSA/SM2 sig algorithms from the crypto framework
 */
void cmh_pke_ecdsa_unregister(void)
{
	int i = ARRAY_SIZE(cmh_ecdsa_algs);

	while (i--)
		crypto_unregister_sig(&cmh_ecdsa_algs[i]);
}
