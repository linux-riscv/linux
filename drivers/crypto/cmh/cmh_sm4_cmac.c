// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API SM4-CMAC / SM4-XCBC (ahash) Driver
 *
 * Registers cmac(sm4) and xcbc(sm4) as ahash algorithms.
 *
 * Both produce a 16-byte tag (MAC) from a key and message.
 * VCQ sequence: [SYS_CMD_WRITE] + SM4_CMD_INIT(CMAC/XCBC) +
 *               SM4_CMD_AAD_FINAL + SM4_CMD_FINAL + FLUSH
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
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

#define SM4_MAC_DIGEST_SIZE	16U
#define SM4_MAC_BLOCK_SIZE	16U
/*
 * Maximum accumulated data for SM4 MAC -- driver-imposed, not HW.
 *
 * The SM4 core does not expose external save/restore VCQ commands,
 * so the driver must accumulate all data in kernel memory via
 * .update() and submit it atomically in .final().  This cap limits
 * the per-request kernel allocation.
 */
#define SM4_MAC_MAX_DATA	(64 * 1024)

struct cmh_sm4_mac_alg_info {
	u32         sm4_mode;	/* SM4_MODE_CMAC or SM4_MODE_XCBC */
	const char *alg_name;
	const char *drv_name;
};

static const struct cmh_sm4_mac_alg_info sm4_mac_algs[] = {
	{ SM4_MODE_CMAC, "cmac(sm4)", "cri-cmh-cmac-sm4" },
	{ SM4_MODE_XCBC, "xcbc(sm4)", "cri-cmh-xcbc-sm4" },
};

struct cmh_sm4_mac_tfm_ctx {
	struct cmh_key_ctx key;
	u32 sm4_mode;
	struct crypto_cipher *sw_cipher;	/* empty-input fallback (CMAC/XCBC) */
	/* Cached subkeys (derived at setkey time for concurrency safety) */
	u8 xcbc_k1[CMH_SM4_BLOCK_SIZE];		/* K1 = E(K, 0x01..01) */
	u8 xcbc_k3[CMH_SM4_BLOCK_SIZE];		/* K3 = E(K, 0x03..03) */
	u8 cmac_k2[CMH_SM4_BLOCK_SIZE];		/* K2 = dbl(dbl(E(K, 0))) */
	bool subkeys_valid;
	spinlock_t         chunk_lock;  /* protects all_chunks */
	struct list_head   all_chunks;  /* orphan-safe chunk tracking */
};

/* Per-request context (lives in ahash_request::__ctx) */
/* Chunk node for O(1) update() appends */
struct cmh_sm4_mac_chunk {
	struct list_head list;
	struct list_head tfm_node; /* per-tfm orphan tracking */
	u32 len;
	u8  data[];
};

/* Per-request context (lives in ahash_request::__ctx) */

#define CMH_SM4_MAC_MAX_PAYLOAD		5
#define CMH_SM4_MAC_MAX_PACKED		(CMH_SM4_MAC_MAX_PAYLOAD * 2)

struct cmh_sm4_mac_reqctx {
	struct list_head chunks;
	u32  total_len;
	u8  *buf;		/* linearised in final() */
	/* DMA state for async final */
	dma_addr_t key_dma;
	dma_addr_t in_dma;
	dma_addr_t tag_dma;
	u8 *tag_buf;
	u32 keylen;
	struct vcq_cmd packed[CMH_SM4_MAC_MAX_PACKED];
};

/* Flat state for export/import -- holds accumulated input data only */
struct cmh_sm4_mac_export_state {
	u32 total_len;
	u8  data[];
};

/*
 * Flat state buffer for export/import.  The CMH SM4 core does not
 * support save/restore of intermediate MAC state, so this driver
 * accumulates input in SW and serialises the buffer on export.
 *
 * PAGE_SIZE (4096) caps the exportable accumulated-data window.
 * Full-range export is not feasible because the crypto subsystem
 * pre-allocates statesize bytes per request.  Export returns -EINVAL
 * if the caller has accumulated more than CMH_SM4_MAC_EXPORT_MAX.
 */
#define CMH_SM4_MAC_STATE_SIZE 4096
#define CMH_SM4_MAC_EXPORT_MAX \
	(CMH_SM4_MAC_STATE_SIZE - sizeof(struct cmh_sm4_mac_export_state))

struct cmh_sm4_mac_drv {
	struct ahash_alg                   alg;
	const struct cmh_sm4_mac_alg_info *info;
};

/*
 * GF(2^128) doubling used to derive the CMAC subkeys (NIST SP 800-38B).
 * Shift the 128-bit big-endian value left by one bit and, if the top bit
 * was set, reduce with Rb = 0x87.
 */
static void cmh_sm4_cmac_dbl(u8 out[CMH_SM4_BLOCK_SIZE],
			     const u8 in[CMH_SM4_BLOCK_SIZE])
{
	u8 carry = in[0] >> 7;
	unsigned int i;

	for (i = 0; i < CMH_SM4_BLOCK_SIZE - 1; i++)
		out[i] = (in[i] << 1) | (in[i + 1] >> 7);
	out[CMH_SM4_BLOCK_SIZE - 1] = (in[CMH_SM4_BLOCK_SIZE - 1] << 1) ^
				      (carry ? 0x87 : 0x00);
}

static int cmh_sm4_mac_setkey(struct crypto_ahash *tfm, const u8 *key,
			      unsigned int keylen)
{
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	int ret;

	if (keylen != CMH_SM4_KEY_SIZE)
		return -EINVAL;

	if (tctx->sw_cipher && tctx->sm4_mode == SM4_MODE_XCBC) {
		u8 const1[CMH_SM4_BLOCK_SIZE], const3[CMH_SM4_BLOCK_SIZE];

		ret = crypto_cipher_setkey(tctx->sw_cipher, key, keylen);
		if (ret)
			return ret;

		/* Pre-derive XCBC subkeys for concurrent-safe final() */
		memset(const1, 0x01, CMH_SM4_BLOCK_SIZE);
		memset(const3, 0x03, CMH_SM4_BLOCK_SIZE);
		crypto_cipher_encrypt_one(tctx->sw_cipher, tctx->xcbc_k1,
					  const1);
		crypto_cipher_encrypt_one(tctx->sw_cipher, tctx->xcbc_k3,
					  const3);

		/*
		 * Leave sw_cipher keyed with K1 permanently.
		 * final() only needs E(K1, block) and never touches the
		 * original key again, so no re-keying in the hot path
		 * eliminates the per-tfm concurrency race entirely.
		 */
		ret = crypto_cipher_setkey(tctx->sw_cipher, tctx->xcbc_k1,
					   CMH_SM4_BLOCK_SIZE);
		if (ret)
			return ret;
	} else if (tctx->sw_cipher && tctx->sm4_mode == SM4_MODE_CMAC) {
		u8 zero[CMH_SM4_BLOCK_SIZE] = { 0 };
		u8 l[CMH_SM4_BLOCK_SIZE], k1[CMH_SM4_BLOCK_SIZE];

		ret = crypto_cipher_setkey(tctx->sw_cipher, key, keylen);
		if (ret)
			return ret;

		/*
		 * Pre-derive the CMAC subkey K2 for the empty-message
		 * fallback (NIST SP 800-38B):
		 *   L = E(K, 0^128); K1 = dbl(L); K2 = dbl(K1)
		 * sw_cipher is left keyed with the original K, so final()
		 * computes E(K, K2 ^ pad) with no hot-path re-keying.
		 */
		crypto_cipher_encrypt_one(tctx->sw_cipher, l, zero);
		cmh_sm4_cmac_dbl(k1, l);
		cmh_sm4_cmac_dbl(tctx->cmac_k2, k1);
		memzero_explicit(l, sizeof(l));
		memzero_explicit(k1, sizeof(k1));
	}

	ret = cmh_key_setkey_raw(&tctx->key, key, keylen, CORE_ID_SM4);
	if (ret)
		return ret;

	if (tctx->sw_cipher)
		tctx->subkeys_valid = true;

	return 0;
}

static void cmh_sm4_mac_free_chunks(struct cmh_sm4_mac_reqctx *rctx,
				    struct cmh_sm4_mac_tfm_ctx *tctx)
{
	struct cmh_sm4_mac_chunk *c, *tmp;

	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(c, tmp, &rctx->chunks, list) {
		list_del(&c->list);
		list_del(&c->tfm_node);
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);
}

static int cmh_sm4_mac_init(struct ahash_request *req)
{
	struct cmh_sm4_mac_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(*rctx));
	INIT_LIST_HEAD(&rctx->chunks);
	return 0;
}

static int cmh_sm4_mac_update(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_sm4_mac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_sm4_mac_chunk *chunk;
	gfp_t gfp;
	int ret;

	if (!req->nbytes)
		return 0;

	if (req->nbytes > SM4_MAC_MAX_DATA - rctx->total_len) {
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
	cmh_sm4_mac_free_chunks(rctx, tctx);
	return ret;
}

static void cmh_sm4_mac_complete(void *data, int error)
{
	struct ahash_request *req = data;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_sm4_mac_reqctx *rctx = ahash_request_ctx(req);

	if (error == -EINPROGRESS) {
		cmh_complete(&req->base, error);
		return;
	}

	if (rctx->total_len > 0)
		cmh_dma_unmap_single(rctx->in_dma, rctx->total_len,
				     DMA_TO_DEVICE);
	cmh_dma_unmap_single(rctx->tag_dma, SM4_MAC_DIGEST_SIZE,
			     DMA_FROM_DEVICE);

	if (!error)
		memcpy(req->result, rctx->tag_buf, SM4_MAC_DIGEST_SIZE);

	kfree(rctx->tag_buf);
	rctx->tag_buf = NULL;
	cmh_sm4_mac_free_chunks(rctx, tctx);
	kfree_sensitive(rctx->buf);
	rctx->buf = NULL;
	rctx->total_len = 0;
	cmh_complete(&req->base, error);
}

static int cmh_sm4_mac_final(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_sm4_mac_reqctx *rctx = ahash_request_ctx(req);
	struct vcq_cmd cmds[CMH_SM4_MAC_MAX_PAYLOAD];
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
		goto out_free_chunks;
	}

	/*
	 * XCBC empty-input SW fallback (RFC 3566).
	 *
	 * For a zero-length message:
	 *   K1 = E(K, 0x01010101...)  -- encryption subkey
	 *   K3 = E(K, 0x03030303...)  -- incomplete-block subkey
	 *   pad = 0x80 00...00        -- single 1 bit + 127 zero bits
	 *   tag = E(K1, pad XOR K3)
	 *
	 * The eSW produces incorrect output for this case, so the driver
	 * computes it synchronously using crypto_cipher.
	 *
	 * For DS keys we cannot derive subkeys (no raw key material),
	 * and the HW also cannot handle empty XCBC correctly, so
	 * return -EOPNOTSUPP.
	 */
	if (rctx->total_len == 0 && tctx->sm4_mode == SM4_MODE_XCBC) {
		u8 block[CMH_SM4_BLOCK_SIZE];
		u32 i;

		if (tctx->key.mode != CMH_KEY_RAW ||
		    !tctx->subkeys_valid) {
			cmh_sm4_mac_free_chunks(rctx, tctx);
			return -EOPNOTSUPP;
		}

		/* block = pad XOR K3 */
		memset(block, 0, CMH_SM4_BLOCK_SIZE);
		block[0] = 0x80;
		for (i = 0; i < CMH_SM4_BLOCK_SIZE; i++)
			block[i] ^= tctx->xcbc_k3[i];

		/*
		 * tag = E(K1, block)
		 *
		 * sw_cipher is permanently keyed with K1 (set at setkey
		 * time), so this is safe for concurrent requests sharing
		 * the same tfm -- no re-keying, no race.
		 */
		crypto_cipher_encrypt_one(tctx->sw_cipher, req->result,
					  block);

		cmh_sm4_mac_free_chunks(rctx, tctx);
		return 0;
	}

	/*
	 * CMAC empty-input SW fallback (NIST SP 800-38B).
	 *
	 * For a zero-length message the sole block is incomplete, so the
	 * K2 subkey is used:
	 *   pad = 0x80 00...00        -- single 1 bit + 127 zero bits
	 *   tag = E(K, pad XOR K2)
	 *
	 * The eSW produces incorrect output for this case, so the driver
	 * computes it synchronously using crypto_cipher.
	 *
	 * For DS keys we cannot derive subkeys (no raw key material),
	 * and the HW also cannot handle empty CMAC correctly, so
	 * return -EOPNOTSUPP.
	 */
	if (rctx->total_len == 0 && tctx->sm4_mode == SM4_MODE_CMAC) {
		u8 block[CMH_SM4_BLOCK_SIZE];
		u32 i;

		if (tctx->key.mode != CMH_KEY_RAW || !tctx->subkeys_valid) {
			cmh_sm4_mac_free_chunks(rctx, tctx);
			return -EOPNOTSUPP;
		}

		/* block = pad XOR K2 */
		memset(block, 0, CMH_SM4_BLOCK_SIZE);
		block[0] = 0x80;
		for (i = 0; i < CMH_SM4_BLOCK_SIZE; i++)
			block[i] ^= tctx->cmac_k2[i];

		/*
		 * tag = E(K, block).  sw_cipher is keyed with the original
		 * key K (set at setkey time, never re-keyed), so this is
		 * safe for concurrent requests sharing the same tfm.
		 */
		crypto_cipher_encrypt_one(tctx->sw_cipher, req->result,
					  block);

		cmh_sm4_mac_free_chunks(rctx, tctx);
		return 0;
	}

	gfp = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
	      GFP_KERNEL : GFP_ATOMIC;

	/* Linearise chunks into a single contiguous buffer for DMA */
	if (rctx->total_len > 0) {
		struct cmh_sm4_mac_chunk *c;
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

	rctx->tag_buf = kzalloc(SM4_MAC_DIGEST_SIZE, gfp);
	if (!rctx->tag_buf) {
		ret = -ENOMEM;
		goto out_free_buf;
	}

	rctx->tag_dma = cmh_dma_map_single(rctx->tag_buf,
					   SM4_MAC_DIGEST_SIZE,
					    DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rctx->tag_dma)) {
		ret = -ENOMEM;
		goto out_free_tag;
	}

	if (rctx->total_len > 0) {
		rctx->in_dma = cmh_dma_map_single(rctx->buf, rctx->total_len,
						  DMA_TO_DEVICE);
		if (cmh_dma_map_error(rctx->in_dma)) {
			ret = -ENOMEM;
			goto out_unmap_tag;
		}
	}

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

	/*
	 * INIT: mode=CMAC or XCBC
	 * CMAC/XCBC data goes through the AAD path:
	 *   aadlen = total data length, iolen = 0
	 */
	{
		struct vcq_cmd *slot = &cmds[idx++];

		memset(slot, 0, sizeof(*slot));
		slot->magic = VCQ_CMD_MAGIC;
		slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_INIT);
		slot->hwc.sm4.cmd_init.key = key_ref;
		slot->hwc.sm4.cmd_init.iv = 0;
		slot->hwc.sm4.cmd_init.keylen = keylen;
		slot->hwc.sm4.cmd_init.ivlen = 0;
		slot->hwc.sm4.cmd_init.mode = tctx->sm4_mode;
		slot->hwc.sm4.cmd_init.op = SM4_OP_ENCRYPT;
		slot->hwc.sm4.cmd_init.aadlen = rctx->total_len;
		slot->hwc.sm4.cmd_init.iolen = 0;
	}

	/* AAD_FINAL: send data through the AAD path */
	if (rctx->total_len > 0) {
		struct vcq_cmd *slot = &cmds[idx++];

		memset(slot, 0, sizeof(*slot));
		slot->magic = VCQ_CMD_MAGIC;
		slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_AAD_FINAL);
		slot->hwc.sm4.cmd_aad_final.data = (u64)rctx->in_dma;
		slot->hwc.sm4.cmd_aad_final.datalen = rctx->total_len;
	}

	/* FINAL: tag extraction only (no data) */
	{
		struct vcq_cmd *slot = &cmds[idx++];

		memset(slot, 0, sizeof(*slot));
		slot->magic = VCQ_CMD_MAGIC;
		slot->id = VCQ_CMD_ID(core_id, 0, 1, SM4_CMD_FINAL);
		slot->hwc.sm4.cmd_final.input = 0;
		slot->hwc.sm4.cmd_final.output = 0;
		slot->hwc.sm4.cmd_final.tag = (u64)rctx->tag_dma;
		slot->hwc.sm4.cmd_final.iolen = 0;
		slot->hwc.sm4.cmd_final.taglen = SM4_MAC_DIGEST_SIZE;
	}

	vcq_add_flush(&cmds[idx++], core_id);

	ret = cmh_vcq_pack_and_submit_async(cmds, idx, rctx->packed,
					    CMH_SM4_MAC_MAX_PACKED,
					    target_mbx,
					    cmh_sm4_mac_complete, req,
					    !!(req->base.flags &
					       CRYPTO_TFM_REQ_MAY_BACKLOG),
					    cmh_tm_async_timeout_jiffies());
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
	cmh_dma_unmap_single(rctx->tag_dma, SM4_MAC_DIGEST_SIZE,
			     DMA_FROM_DEVICE);
out_free_tag:
	kfree(rctx->tag_buf);
out_free_buf:
	kfree_sensitive(rctx->buf);
	rctx->buf = NULL;
out_free_chunks:
	cmh_sm4_mac_free_chunks(rctx, tctx);
	rctx->total_len = 0;
	return ret;
}

/*
 * ahash .export()/.import(): serialize/deserialize the software
 * accumulation buffer.  No HW state is involved.
 */

static int cmh_sm4_mac_export(struct ahash_request *req, void *out)
{
	struct cmh_sm4_mac_reqctx *rctx = ahash_request_ctx(req);
	struct cmh_sm4_mac_export_state *state = out;
	struct cmh_sm4_mac_chunk *chunk;
	u32 offset = 0;

	if (rctx->total_len > CMH_SM4_MAC_EXPORT_MAX)
		return -ENOSPC;

	state->total_len = rctx->total_len;
	list_for_each_entry(chunk, &rctx->chunks, list) {
		memcpy(state->data + offset, chunk->data, chunk->len);
		offset += chunk->len;
	}
	return 0;
}

static int cmh_sm4_mac_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_sm4_mac_reqctx *rctx = ahash_request_ctx(req);
	const struct cmh_sm4_mac_export_state *state = in;
	struct cmh_sm4_mac_chunk *chunk;

	/*
	 * Do NOT call free_chunks() here: the crypto API does not
	 * guarantee the request context is in a valid state before
	 * import(), so the list pointers may be stale or invalid.
	 * Re-initialize from scratch instead.  Any pre-existing chunks
	 * are tracked on tctx->all_chunks and freed in exit_tfm.
	 */
	memset(rctx, 0, sizeof(*rctx));
	INIT_LIST_HEAD(&rctx->chunks);

	if (state->total_len > CMH_SM4_MAC_EXPORT_MAX)
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

static int cmh_sm4_mac_finup(struct ahash_request *req)
{
	int err;

	err = cmh_sm4_mac_update(req);
	if (err)
		return err;
	return cmh_sm4_mac_final(req);
}

static int cmh_sm4_mac_digest(struct ahash_request *req)
{
	int err;

	err = cmh_sm4_mac_init(req);
	if (err)
		return err;
	return cmh_sm4_mac_finup(req);
}

/* Registration */

static struct cmh_sm4_mac_drv sm4_mac_drv_algs[ARRAY_SIZE(sm4_mac_algs)];

static int cmh_sm4_mac_init_tfm(struct crypto_ahash *tfm)
{
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct ahash_alg *alg = crypto_ahash_alg(tfm);
	struct cmh_sm4_mac_drv *drv =
		container_of(alg, struct cmh_sm4_mac_drv, alg);

	memset(tctx, 0, sizeof(*tctx));
	tctx->sm4_mode = drv->info->sm4_mode;
	spin_lock_init(&tctx->chunk_lock);
	INIT_LIST_HEAD(&tctx->all_chunks);

	/* Allocate SW cipher for the CMAC/XCBC empty-input fallback */
	if (tctx->sm4_mode == SM4_MODE_XCBC ||
	    tctx->sm4_mode == SM4_MODE_CMAC) {
		struct crypto_cipher *ci;

		ci = crypto_alloc_cipher("sm4", 0, 0);
		if (IS_ERR(ci))
			return PTR_ERR(ci);
		tctx->sw_cipher = ci;
	}

	crypto_ahash_set_reqsize(tfm, sizeof(struct cmh_sm4_mac_reqctx));
	return 0;
}

static void cmh_sm4_mac_exit_tfm(struct crypto_ahash *tfm)
{
	struct cmh_sm4_mac_tfm_ctx *tctx = crypto_ahash_ctx(tfm);
	struct cmh_sm4_mac_chunk *c, *tmp;

	/* Free any orphaned chunks (e.g. testmgr export/reimport poison) */
	spin_lock_bh(&tctx->chunk_lock);
	list_for_each_entry_safe(c, tmp, &tctx->all_chunks, tfm_node) {
		list_del(&c->tfm_node);
		kfree_sensitive(c);
	}
	spin_unlock_bh(&tctx->chunk_lock);

	if (tctx->sw_cipher)
		crypto_free_cipher(tctx->sw_cipher);
	memzero_explicit(tctx->xcbc_k1, sizeof(tctx->xcbc_k1));
	memzero_explicit(tctx->xcbc_k3, sizeof(tctx->xcbc_k3));
	memzero_explicit(tctx->cmac_k2, sizeof(tctx->cmac_k2));
	cmh_key_destroy(&tctx->key);
}

/**
 * cmh_sm4_cmac_register() - Register SM4-CMAC/XCBC hash algorithms with the crypto framework
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_sm4_cmac_register(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(sm4_mac_algs); i++) {
		const struct cmh_sm4_mac_alg_info *info = &sm4_mac_algs[i];
		struct cmh_sm4_mac_drv *drv = &sm4_mac_drv_algs[i];
		struct ahash_alg *alg = &drv->alg;

		drv->info = info;

		memset(alg, 0, sizeof(*alg));

		alg->init       = cmh_sm4_mac_init;
		alg->update     = cmh_sm4_mac_update;
		alg->final      = cmh_sm4_mac_final;
		alg->finup      = cmh_sm4_mac_finup;
		alg->digest     = cmh_sm4_mac_digest;
		alg->export     = cmh_sm4_mac_export;
		alg->import     = cmh_sm4_mac_import;
		alg->setkey     = cmh_sm4_mac_setkey;
		alg->init_tfm   = cmh_sm4_mac_init_tfm;
		alg->exit_tfm   = cmh_sm4_mac_exit_tfm;

		alg->halg.digestsize = SM4_MAC_DIGEST_SIZE;
		alg->halg.statesize = CMH_SM4_MAC_STATE_SIZE;

		strscpy(alg->halg.base.cra_name, info->alg_name,
			CRYPTO_MAX_ALG_NAME);
		strscpy(alg->halg.base.cra_driver_name, info->drv_name,
			CRYPTO_MAX_ALG_NAME);
		alg->halg.base.cra_priority  = 300;
		alg->halg.base.cra_flags     = CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_NO_FALLBACK |
						CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_REQ_VIRT;
		alg->halg.base.cra_blocksize = SM4_MAC_BLOCK_SIZE;
		alg->halg.base.cra_ctxsize  = sizeof(struct cmh_sm4_mac_tfm_ctx);
		alg->halg.base.cra_module   = THIS_MODULE;

		ret = crypto_register_ahash(alg);
		if (ret) {
			dev_err(cmh_dev(), "cmh_sm4_mac: failed to register %s (rc=%d)\n",
				info->alg_name, ret);
			goto err_unregister;
		}

		dev_dbg(cmh_dev(), "cmh_sm4_mac: registered %s\n",
			info->alg_name);
	}

	return 0;

err_unregister:
	while (i--)
		crypto_unregister_ahash(&sm4_mac_drv_algs[i].alg);
	return ret;
}

/**
 * cmh_sm4_cmac_unregister() - Unregister SM4 MAC hash algorithms from the crypto framework
 */
void cmh_sm4_cmac_unregister(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sm4_mac_algs); i++) {
		crypto_unregister_ahash(&sm4_mac_drv_algs[i].alg);
		dev_dbg(cmh_dev(), "cmh_sm4_mac: unregistered %s\n",
			sm4_mac_algs[i].alg_name);
	}
}
