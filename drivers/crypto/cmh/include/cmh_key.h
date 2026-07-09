/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Per-transform key context
 *
 * Per-transform key context used by all keyed crypto algorithms (AES,
 * SM4, CCP, HMAC, KMAC).  Stores raw key bytes supplied via the crypto
 * API .setkey() callback: the key is DMA-mapped once at setkey time and
 * written to SYS_REF_TEMP in every VCQ.
 *
 * Each keyed algorithm driver embeds a struct cmh_key_ctx in its
 * per-transform context and calls cmh_key_setkey_raw() from its
 * .setkey() callback.
 *
 * Raw-key atomicity (SYS_REF_TEMP)
 * ---------------------------------
 * SYS_CMD_WRITE to SYS_REF_TEMP is packed into the same VCQ as the
 * algorithm commands (AES_CMD_INIT, HC_CMD_HMAC, etc.).  SYS_REF_TEMP
 * is per-MBX -- the CMH eSW allocates it in the tail of each mailbox's
 * own VCQ buffer (mbx_alloc_temp), so concurrent raw-key requests on
 * different MBXes do not interfere.
 */

#ifndef CMH_KEY_H
#define CMH_KEY_H

#include <linux/types.h>
#include "cmh_config.h"
#include "cmh_vcq.h"

/* Key context mode */
enum cmh_key_mode {
	CMH_KEY_NONE = 0,	/* no key set yet */
	CMH_KEY_RAW,		/* raw key bytes in memory */
};

/* Per-transform key context */
struct cmh_key_ctx {
	enum cmh_key_mode mode;
	struct {
		u8 *data;	/* kmemdup'd raw key bytes */
		u32 len;	/* key length in bytes */
		u32 sys_type;	/* SYS_TYPE_SET(flags, core_id) */
		dma_addr_t dma;	/* pre-mapped DMA addr (DMA_TO_DEVICE) */
	} raw;
};

/**
 * cmh_key_setkey_raw() - Store raw key bytes in the transform context
 * @ctx: Per-transform key context
 * @key: Raw key bytes
 * @keylen: Key length in bytes
 * @core_id: Target algorithm core (e.g. CORE_ID_AES)
 *
 * SYS_TYPE_FLAG_PT is set so the written temp key
 * can be read back as plaintext if needed.  The actual SYS_CMD_WRITE
 * to SYS_REF_TEMP is deferred to each encrypt/decrypt VCQ, where it
 * is packed inline for atomicity.
 *
 * Return: 0 on success, -ENOMEM on allocation failure.
 */
int cmh_key_setkey_raw(struct cmh_key_ctx *ctx, const u8 *key,
		       u32 keylen, u32 core_id);

/**
 * cmh_key_destroy() - Free key resources
 * @ctx: Per-transform key context
 *
 * Zeroises and frees the raw key buffer.
 */
void cmh_key_destroy(struct cmh_key_ctx *ctx);

/**
 * cmh_ds_type_to_core_id() - Map datastore key type to core ID
 * @ds_type: CMH_DS_* key type constant
 *
 * Return: Corresponding CORE_ID_*, or CORE_ID_NUM (0x1F) on
 *         unrecognised type (caller should return -EINVAL).
 */
u32 cmh_ds_type_to_core_id(u32 ds_type);

#endif /* CMH_KEY_H */
