/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- KIC Core ABI Definitions
 *
 * Kernel-side definitions for the CMH KIC ABI (KIC commands only).
 * Derived from the CMH eSW ABI.
 */

#ifndef CMH_KIC_ABI_H
#define CMH_KIC_ABI_H

#include <linux/types.h>

/* KIC Commands */

#define KIC_CMD_HKDF1		0x06U
#define KIC_CMD_HKDF2		0x07U
#define KIC_CMD_AES_CMAC_KDF	0x08U
#define KIC_CMD_DKEK_DERIVE	0x09U

/* Maximum key size for KIC operations (bytes) */
#define KIC_KEY_SIZE		32U

/*
 * KIC Command Structures
 *
 * Field names (llen, len) mirror the CMH eSW ABI register layout.
 * llen = label length, len = output key length.
 */

struct kic_cmd_hkdf1 {
	u64 dst;	/* DS ref for derived key (SYS_REF_LAST) */
	u64 base;	/* base key reference (e.g., KIC_KEY1) */
	u64 label;	/* label pointer (0 for inline-next-slot) */
	u32 llen;	/* label length */
	u32 len;		/* output key length */
	u32 type;	/* SYS_TYPE_SET(flags, core_id) */
};

struct kic_cmd_hkdf2 {
	u64 dst;	/* DS ref for derived key */
	u64 base;	/* base key reference */
	u64 salt;	/* salt key reference (SYS_REF_NONE = no salt) */
	u64 label;	/* label pointer */
	u32 llen;	/* label length */
	u32 len;		/* output key length */
	u32 type;	/* SYS_TYPE_SET(flags, core_id) */
};

struct kic_cmd_aes_cmac_kdf {
	u64 base_key;	/* KIC/DS reference for base key */
	u64 out_key;	/* DS reference for derived key */
	u64 label;	/* label DMA address */
	u32 key_len;	/* base & output key length (must be 32) */
	u32 label_len;	/* label length */
	u32 type;	/* SYS_TYPE_SET(flags, core_id) for output */
};

struct kic_cmd_dkek_derive {
	u64 base_key;		/* KIC base key reference */
	u64 out_key;		/* DS reference for the derived KEK */
	u32 host_id;		/* host ID (0 = caller's own) */
	u32 metadata_len;	/* metadata length */
	u64 metadata;		/* metadata DMA address */
};

/* KIC Command Union */

union kic_cmd {
	struct kic_cmd_hkdf1 cmd_hkdf1;
	struct kic_cmd_hkdf2 cmd_hkdf2;
	struct kic_cmd_aes_cmac_kdf cmd_aes_cmac_kdf;
	struct kic_cmd_dkek_derive cmd_dkek_derive;
};

#endif /* CMH_KIC_ABI_H */
