/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SYS Core ABI Definitions
 *
 * Kernel-side definitions for the CMH SYS ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_SYS_ABI_H
#define CMH_SYS_ABI_H

#include <linux/bits.h>
#include <linux/types.h>

/* SYS Commands (per CMH SYS ABI) */

#define SYS_CMD_RUN		0x01U
#define SYS_CMD_NOP		0x02U
#define SYS_CMD_IMPORT		0x07U
#define SYS_CMD_EXPORT		0x08U
#define SYS_CMD_NEW		0x0AU
#define SYS_CMD_READ		0x0BU
#define SYS_CMD_WRITE		0x0CU
#define SYS_CMD_GRANT		0x0DU
#define SYS_CMD_LIST		0x0EU
#define SYS_CMD_FIND		0x0FU
#define SYS_CMD_DATA		0x11U

/* SYS Reference Constants */

#define SYS_REF_NONE		0x0000000000000000ULL
#define SYS_REF_TEMP		0x1111111111111111ULL
#define SYS_REF_LAST		0xFFFFFFFFFFFFFFFFULL

typedef u64 sys_ref_t;

/* SYS CID */

#define SYS_CID_NONE		0x0000000000000000ULL

/* SYS Type Encoding -- bits [7:0] = core_id, bits [23:16] = flags */

#define SYS_TYPE_FLAG_PT	BIT(16)  /* can be read as plaintext */
#define SYS_TYPE_FLAG_XC	BIT(17)  /* can be exported over XC bus */
#define SYS_TYPE_FLAG_SCA	BIT(18)  /* SCA key in 2 shares */

#define SYS_TYPE_SET(flags, core) \
	(((flags) & 0xFF0000UL) | ((core) & 0xFFUL))
#define SYS_TYPE_CORE(type)	((type) & 0xFFU)
#define SYS_TYPE_FLAGS(type)	((type) & 0xFF0000U)
#define SYS_TYPE_NONE		0U	/* DMA output, no DS storage */

#define SYS_WRAP_HDR_SIZE	16	/* sys_read plaintext header */

/* SYS Command Structures */

struct sys_cmd_new {
	u64 cid;	/* caller id (name) for the object */
	u64 ref;	/* DMA address -- CMH eSW writes back reference here */
	u32 len;	/* size of the new object in bytes */
};

struct sys_cmd_write {
	u64 ref;	/* object datastore reference */
	u64 src;	/* DMA source address of key data */
	u64 key;	/* wrapping key reference (SYS_REF_NONE = plaintext) */
	u32 len;	/* source buffer length */
	u32 type;	/* SYS_TYPE_SET(flags, core_id) */
};

struct sys_cmd_read {
	u64 ref;	/* object datastore reference */
	u64 dst;	/* DMA destination for key data */
	u64 key;	/* wrapping key reference (SYS_REF_NONE = plaintext) */
	u32 len;	/* destination buffer length */
};

struct sys_cmd_data {
	u64 ref;	/* object datastore reference */
	u64 dst;	/* DMA destination for object data */
	u32 len;	/* destination buffer length */
};

struct sys_cmd_find {
	u64 cid;	/* caller id to search for */
	u64 dst;	/* DMA destination for struct sys_list_item */
	u32 len;	/* destination buffer length */
};

struct sys_cmd_list {
	u64 ref;	/* starting DS reference (SYS_REF_NONE = first) */
	u64 dst;	/* DMA destination for struct sys_list_item */
	u32 len;	/* destination buffer length */
};

struct sys_cmd_grant {
	u64 ref;	/* object datastore reference */
	u64 read;	/* bitfield: allow read for mailboxes */
	u64 write;	/* bitfield: allow write for mailboxes */
	u64 execute;	/* bitfield: allow use for mailboxes */
};

struct sys_cmd_export {
	u64 cid;	/* caller id for the response */
	u64 dst;	/* DMA destination for the export blob */
	u64 key;	/* wrapping key datastore reference */
	u32 len;	/* destination buffer length */
};

struct sys_cmd_import {
	u64 src;	/* DMA source address of import blob */
	u64 key;	/* wrapping key datastore reference */
	u32 len;	/* source buffer length */
};

/* SYS List/Find Response Item */

struct sys_list_item {
	u64 ref;	/* object datastore reference */
	u64 cid;	/* caller id */
	u32 len;	/* object length */
	u32 type;	/* object type (SYS_TYPE_SET packed) */
};

/* Wrapped-read header (prepended to SYS_CMD_READ responses) */

struct sys_wrap_hdr {
	u64 cid;	/* caller id */
	u32 wrap;	/* wrap data length following this header */
	u32 len;	/* object data length following wrap data */
};

/* SYS Command Union */

union sys_cmd {
	struct sys_cmd_new	cmd_new;
	struct sys_cmd_write	cmd_write;
	struct sys_cmd_read	cmd_read;
	struct sys_cmd_data	cmd_data;
	struct sys_cmd_find	cmd_find;
	struct sys_cmd_list	cmd_list;
	struct sys_cmd_grant	cmd_grant;
	struct sys_cmd_export	cmd_export;
	struct sys_cmd_import	cmd_import;
};

#endif /* CMH_SYS_ABI_H */
