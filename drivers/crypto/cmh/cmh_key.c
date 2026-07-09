// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Dual Key Path Implementation
 *
 * Two key provisioning paths are supported:
 *
 * Raw key:  key bytes -> stored in tfm context ->
 *   SYS_CMD_WRITE(SYS_REF_TEMP) packed into every crypto VCQ.
 *   The raw key buffer is DMA-mapped once at setkey time and remains
 *   mapped for the lifetime of the transform (unmapped in destroy).
 *
 * Raw key DMA lifetime rationale
 * ------------------------------
 * Raw keys are DMA-mapped at setkey time and the mapping persists
 * until the transform is destroyed (cmh_key_destroy).  This is a
 * deliberate design choice, consistent with upstream HW crypto
 * drivers (CAAM, ccree, CCP) that also map keys at setkey for
 * transform-lifetime reuse:
 *
 *   - The Linux crypto framework expects setkey to prepare the
 *     transform for repeated encrypt/decrypt calls.  Remapping the
 *     same key on every request would add DMA API overhead per crypto
 *     operation with no security benefit.
 *   - On destroy, kfree_sensitive() scrubs the key buffer and the
 *     DMA mapping is released.  For key-by-ID (persistent), the
 *     per-MBX ref cache is zeroed with memzero_explicit().
 *   - No key material is ever logged; dev_dbg() messages only show
 *     CIDs (content identifiers), not key bytes.
 *
 * Hardware-required behaviors (not driver policy)
 * ------------------------------------------------
 * - SYS_REF_TEMP lifetime:  the eSW firmware reclaims temporary
 *   datastore objects when the mailbox slot is reused.  This is a
 *   hardware constraint; the driver packs SYS_CMD_WRITE into every
 *   VCQ to re-provision the raw key for each operation.
 * - Mailbox flush (SYS_CMD_FLUSH):  reclaims temp-stack space on the
 *   target MBX.  Required by HW to prevent temp-stack exhaustion
 *   across multi-VCQ operations.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cmh_key.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_dma.h"
#include "cmh_sys_abi.h"
#include <uapi/linux/cmh_mgmt_ioctl.h>

/**
 * cmh_ds_type_to_core_id() - Map a datastore type to a logical core ID
 * @ds_type: Datastore type constant (e.g. CMH_DS_AES_KEY, CMH_DS_SM4_KEY)
 *
 * Returns the algorithm-family identity (e.g. CORE_ID_AES = 0x03), NOT the
 * VCQ dispatch core_id.  With multi-instance, a second AES engine dispatches
 * at CORE_ID_AES2 (0x06) but keys are still tagged with CORE_ID_AES (0x03)
 * -- the eSW validates against the logical identity, not the dispatch ID.
 *
 * Return: Logical core ID on success, CORE_ID_NUM for unknown @ds_type.
 */
u32 cmh_ds_type_to_core_id(u32 ds_type)
{
	switch (ds_type) {
	case CMH_DS_AES_KEY:
	case CMH_DS_AES_XTS_KEY:
		return CORE_ID_AES;
	case CMH_DS_SM4_KEY:
		return CORE_ID_SM4;
	case CMH_DS_HMAC_KEY:
	case CMH_DS_KMAC_KEY:
		return CORE_ID_HC;
	case CMH_DS_CHACHA20_KEY:
		return CORE_ID_CCP;
	case CMH_DS_RSA_PRIV_KEY:
	case CMH_DS_RSA_PUB_KEY:
	case CMH_DS_RSA_CRT_KEY:
	case CMH_DS_ECDSA_PRIV_KEY:
	case CMH_DS_ECDSA_PUB_KEY:
	case CMH_DS_ECDH_PRIV_KEY:
	case CMH_DS_EDDSA_PRIV_KEY:
	case CMH_DS_SHARED_SECRET:
	case CMH_DS_SM2_PRIV_KEY:
		return CORE_ID_PKE;
	case CMH_DS_ML_KEM_DK:
	case CMH_DS_ML_DSA_SK:
		return CORE_ID_QSE;
	case CMH_DS_SLHDSA_SK:
		return CORE_ID_HCQ;
	default:
		return CORE_ID_NUM;
	}
}

/**
 * cmh_key_setkey_raw() - Store a raw key in the key context
 * @ctx: Key context to populate
 * @key: Pointer to the raw key bytes
 * @keylen: Length of @key in bytes
 * @core_id: Logical core ID for SYS_TYPE tagging
 *
 * Duplicates the raw key, DMA-maps the copy for the lifetime of the
 * transform, and stores the mapping in @ctx.  Any previously held key
 * is destroyed first.
 *
 * The DMA mapping persists until cmh_key_destroy() is called (typically
 * from the algorithm .exit_tfm callback).  This avoids per-request DMA
 * mapping overhead and matches the setkey-to-destroy lifetime model used
 * by other upstream HW crypto drivers (CAAM, ccree, CCP).  The key
 * buffer is freed via kfree_sensitive() on destroy.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_key_setkey_raw(struct cmh_key_ctx *ctx, const u8 *key,
		       u32 keylen, u32 core_id)
{
	dma_addr_t dma;
	u8 *copy;

	if (!keylen || !key)
		return -EINVAL;

	copy = kmemdup(key, keylen, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	/* Pre-map for the lifetime of the transform */
	dma = cmh_dma_map_single(copy, keylen, DMA_TO_DEVICE);
	if (cmh_dma_map_error(dma)) {
		kfree_sensitive(copy);
		return -ENOMEM;
	}

	/* Clean up any previous key */
	cmh_key_destroy(ctx);

	ctx->mode = CMH_KEY_RAW;
	ctx->raw.data = copy;
	ctx->raw.len = keylen;
	ctx->raw.dma = dma;
	ctx->raw.sys_type = SYS_TYPE_SET(SYS_TYPE_FLAG_PT, core_id);

	return 0;
}

/**
 * cmh_key_destroy() - Destroy and zero-fill a key context
 * @ctx: Key context to destroy
 *
 * For raw keys, unmaps the DMA buffer and securely frees the key material.
 * Resets the key mode to CMH_KEY_NONE.
 */
void cmh_key_destroy(struct cmh_key_ctx *ctx)
{
	if (ctx->mode == CMH_KEY_RAW && ctx->raw.data) {
		cmh_dma_unmap_single(ctx->raw.dma, ctx->raw.len,
				     DMA_TO_DEVICE);
		kfree_sensitive(ctx->raw.data);
		memzero_explicit(&ctx->raw, sizeof(ctx->raw));
	}
	ctx->mode = CMH_KEY_NONE;
}
