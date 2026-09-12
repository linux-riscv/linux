/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * This file is exported by OP-TEE and is kept in sync between secure world
 * and normal world drivers. It describes the wire contract used when
 * communicating with secure world OP-TEE OS over the RPMI TEE service group
 * (RPMI specification section 4.16, SERVICEGROUP_ID 0x0010).
 *
 * The RPMI TEE service group is the RISC-V analog of Arm FF-A: OP-TEE and the
 * rich execution environment (REE, i.e. Linux) are peer endpoints, and the
 * RPMI framework (OpenSBI in M-mode) mediates every message. Memory sharing
 * follows the FF-A memory-donation model through the memory parcel services:
 * the REE creates a parcel describing its pages, OP-TEE accepts it lazily by
 * parcel id, and teardown is two phased (OP-TEE releases, the REE reclaims).
 *
 * All request and response payloads are little-endian uint32 words as defined
 * by the RPMI specification. These definitions MUST byte-match the OpenSBI
 * framework definitions in <sbi_utils/mailbox/rpmi_msgprot.h>.
 */

#ifndef __OPTEE_RISCV_H
#define __OPTEE_RISCV_H

#include <linux/bits.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/types.h>

/*
 * RPMI TEE service ids (RPMI spec section 4.16, Table 181).
 *
 * Only TEE_ENABLE_NOTIFICATION, TEE_PROBE_FEATURES and TEE_CALL are mandated;
 * the remaining services are optional and may return RPMI_ERR_NOTSUPP.
 */
enum rpmi_tee_service_id {
	RPMI_TEE_SRV_ENABLE_NOTIFICATION	= 0x01,
	RPMI_TEE_SRV_PROBE_FEATURES		= 0x02,
	RPMI_TEE_SRV_PROBE_SYSTEM		= 0x03,
	RPMI_TEE_SRV_EXIT			= 0x04,
	RPMI_TEE_SRV_SIGNAL_BUS_SETUP		= 0x05,
	RPMI_TEE_SRV_SIGNAL_BUS_TEARDOWN	= 0x06,
	RPMI_TEE_SRV_SIGNAL_RAISE		= 0x07,
	RPMI_TEE_SRV_SIGNAL_RETRIEVE		= 0x08,
	RPMI_TEE_SRV_MEM_PARCEL_CREATE		= 0x09,
	RPMI_TEE_SRV_MEM_PARCEL_ACCEPT		= 0x0a,
	RPMI_TEE_SRV_MEM_PARCEL_RELEASE		= 0x0b,
	RPMI_TEE_SRV_MEM_PARCEL_RECLAIM		= 0x0c,
	RPMI_TEE_SRV_MEM_PARCEL_SEGMENT_SEND	= 0x0d,
	RPMI_TEE_SRV_MEM_PARCEL_SEGMENT_RECEIVE	= 0x0e,
	RPMI_TEE_SRV_CALL			= 0x13,
	RPMI_TEE_SRV_MAX_COUNT,
};

/*
 * RPMI TEE endpoint identities.
 *
 * The RPMI specification does not fix numeric endpoint ids; they are assigned
 * by the framework at runtime. These values match the OpenSBI framework
 * assignment used on this platform: the REE is endpoint 0 and OP-TEE is
 * endpoint 1.
 */
#define RPMI_TEE_ENDPOINT_REE		0
#define RPMI_TEE_ENDPOINT_OPTEE		1

/*
 * RPMI TEE feature ids for TEE_PROBE_FEATURES (RPMI spec section 4.16.4,
 * Table 182).
 */
enum rpmi_tee_feature_id {
	RPMI_TEE_FEAT_MEMORY_DONATE	= 1,
	RPMI_TEE_FEAT_MEMORY_LEND	= 2,
	RPMI_TEE_FEAT_MEMORY_SHARE	= 3,
	RPMI_TEE_FEAT_SIGNAL_BUS	= 4,
	RPMI_TEE_FEAT_MULTISEGMENT_OPS	= 5,
	RPMI_TEE_FEAT_SYSINFO_FORMAT	= 6,
};

/* MEMORY_SHARE feature values (RPMI spec Table 182). */
#define RPMI_TEE_MEMORY_SHARE_NONE		0
#define RPMI_TEE_MEMORY_SHARE_TEE_ONLY		1
#define RPMI_TEE_MEMORY_SHARE_FULL		2

/* TEE_PROBE_FEATURES request (Table 183) / response (Table 184). */
struct rpmi_tee_probe_features_req {
	__le32 feature_id;
};

struct rpmi_tee_probe_features_resp {
	__le32 status;
	__le32 value;
};

/*
 * TEE_CALL wire encoding (RPMI spec section 4.16.21, Tables 218 and 219).
 *
 * TEE_CALL is the mandatory doorbell service used to enter OP-TEE. The
 * request carries a fixed REE->OP-TEE identity, the well-known OP-TEE service
 * UUID and a SERVICE_DATA payload; the response carries a STATUS word, a
 * SERVICE_RSP_LEN word and the SERVICE_RSP payload.
 *
 * The SERVICE_DATA/SERVICE_RSP registers are XLEN-sized little-endian values.
 * The structures are __packed so the 16-byte UUID does not force padding
 * before the length word.
 */
#define RPMI_TEE_UUID_LEN		16

/* OP-TEE communicate service UUID: 5be1b1a0-7e11-4e7a-9b10-0010c0ffee00 */
#define RPMI_TEE_OPTEE_UUID						\
	{ 0x5b, 0xe1, 0xb1, 0xa0, 0x7e, 0x11, 0x4e, 0x7a,		\
	  0x9b, 0x10, 0x00, 0x10, 0xc0, 0xff, 0xee, 0x00 }

/*
 * OP-TEE FF-A direct message convention carried inside SERVICE_DATA:
 * five command words each way, the RISC-V analog of the FF-A data0-data4
 * (w3-w7) set of struct ffa_send_direct_data.
 */
#define RPMI_TEE_OPTEE_CALL_REGS	5
#define RPMI_TEE_OPTEE_RESP_REGS	5

#if __riscv_xlen == 64
typedef __le64 rpmi_xlen_t;
#define cpu_to_rpmi_xlen(x)	cpu_to_le64(x)
#define rpmi_xlen_to_cpu(x)	le64_to_cpu(x)
#else
typedef __le32 rpmi_xlen_t;
#define cpu_to_rpmi_xlen(x)	cpu_to_le32(x)
#define rpmi_xlen_to_cpu(x)	le32_to_cpu(x)
#endif

struct rpmi_tee_call_req {
	__le32 sender_id;
	__le32 target_id;
	u8 service[RPMI_TEE_UUID_LEN];
	__le32 service_data_len;
	rpmi_xlen_t reg[RPMI_TEE_OPTEE_CALL_REGS];
} __packed;

struct rpmi_tee_call_resp {
	__le32 status;
	__le32 service_rsp_len;
	rpmi_xlen_t reg[RPMI_TEE_OPTEE_RESP_REGS];
} __packed;

/*
 * OP-TEE message ABI carried inside the TEE_CALL SERVICE_DATA words.
 *
 * This mirrors the FF-A message ABI in <optee_ffa.h>: OP-TEE and the REE are
 * peer endpoints and the argument struct optee_msg_arg is passed by shared
 * memory handle (a parcel id) plus an offset, never by a register block. The
 * SERVICE_DATA registers carry a small command word set that is the RISC-V
 * analog of the FF-A w3-w7 register usage:
 *
 *   reg[0]: command / service id  (OPTEE_ABI_YIELDING_CALL_* below)
 *   reg[1]: shared memory handle, lower 32 bits (parcel id)
 *   reg[2]: shared memory handle, upper 32 bits (parcel nonce)
 *   reg[3]: offset into the shared memory to the struct optee_msg_arg
 *   reg[4]: not used on this call, resume info on OPTEE_ABI_YIELDING_CALL_RESUME
 *
 * On return the SERVICE_RSP registers carry:
 *   reg[0]: error code, 0 on success
 *   reg[1]: return code (OPTEE_ABI_YIELDING_CALL_RETURN_* below)
 *   reg[2..3]: not used
 *   reg[4]: RPC resume info
 *
 * These MUST byte-match the secure world OP-TEE header.
 */
#define OPTEE_ABI_BLOCKING_CALL(id)	(id)
#define OPTEE_ABI_YIELDING_CALL_BIT	31
#define OPTEE_ABI_YIELDING_CALL(id)	((id) | BIT(OPTEE_ABI_YIELDING_CALL_BIT))

/* Blocking (fast) calls, mirror of OPTEE_FFA_BLOCKING_CALL ids. */
#define OPTEE_ABI_GET_API_VERSION	OPTEE_ABI_BLOCKING_CALL(0)
#define OPTEE_ABI_GET_OS_VERSION	OPTEE_ABI_BLOCKING_CALL(1)
#define OPTEE_ABI_EXCHANGE_CAPABILITIES	OPTEE_ABI_BLOCKING_CALL(2)
#define OPTEE_ABI_UNREGISTER_SHM	OPTEE_ABI_BLOCKING_CALL(3)
#define OPTEE_ABI_ENABLE_ASYNC_NOTIF	OPTEE_ABI_BLOCKING_CALL(5)

/* OP-TEE ABI version, mirror of OPTEE_FFA_VERSION_*. */
#define OPTEE_ABI_VERSION_MAJOR		1
#define OPTEE_ABI_VERSION_MINOR		0

/* Capabilities returned by EXCHANGE_CAPABILITIES (OPTEE_FFA_SEC_CAP_* analog). */
#define OPTEE_ABI_SEC_CAP_ARG_OFFSET	BIT(0)
#define OPTEE_ABI_SEC_CAP_ASYNC_NOTIF	BIT(1)
#define OPTEE_ABI_SEC_CAP_RPMB_PROBE	BIT(2)

#define OPTEE_ABI_MAX_ASYNC_NOTIF_VALUE	64

/* Yielding calls, mirror of OPTEE_FFA_YIELDING_CALL_*. */
#define OPTEE_ABI_YIELDING_CALL_WITH_ARG	OPTEE_ABI_YIELDING_CALL(0)
#define OPTEE_ABI_YIELDING_CALL_RESUME		OPTEE_ABI_YIELDING_CALL(1)

#define OPTEE_ABI_YIELDING_CALL_RETURN_DONE		0
#define OPTEE_ABI_YIELDING_CALL_RETURN_RPC_CMD		1
#define OPTEE_ABI_YIELDING_CALL_RETURN_INTERRUPT	2

/*
 * Memory parcel wire encodings (RPMI spec section 4.16, Tables 198-207).
 *
 * A memory parcel is the RISC-V analog of an FF-A memory-share handle: the REE
 * creates a parcel describing its pages and OP-TEE accepts it lazily by parcel
 * id. All fields are little-endian uint32 words; block-list addresses are
 * expressed in units of 4kB pages.
 */

/* Memory access encoding (Table 199). */
#define RPMI_TEE_PARCEL_ACCESS_R	BIT(29)
#define RPMI_TEE_PARCEL_ACCESS_W	BIT(30)
#define RPMI_TEE_PARCEL_ACCESS_X	BIT(31)

/* MEM_PARCEL_CREATE flags (Table 200). */
#define RPMI_TEE_PARCEL_CREATE_FLAG_MULTI_SEGMENT	BIT(31)
#define RPMI_TEE_PARCEL_CREATE_FLAG_OWNER_XFER		BIT(30)

/* Length of the parcel LABEL field (Table 200). */
#define RPMI_TEE_PARCEL_LABEL_LEN	16

/*
 * A block list entry covers a run of physically contiguous 4kB pages
 * (Table 198):
 *   BLOCK_HIGH = page-frame number [51:20]
 *   BLOCK_LOW  = (page-frame number [19:0] << 12) | (page count - 1)
 * so a single block spans at most 4096 pages (16MB).
 */
#define RPMI_TEE_PARCEL_BLOCK_MAX_PAGES	4096

static inline __le32 rpmi_tee_block_high(u64 pfn)
{
	return cpu_to_le32((u32)(pfn >> 20));
}

static inline __le32 rpmi_tee_block_low(u64 pfn, u32 npages)
{
	return cpu_to_le32(((u32)(pfn & 0xfffff) << 12) | (npages - 1));
}

/*
 * MEM_PARCEL_CREATE request (Table 200): a fixed header followed by
 * receiver_id[receiver_cnt], access[receiver_cnt], block_high[block_cnt] and
 * block_low[block_cnt].
 */
struct rpmi_tee_mem_parcel_create_req {
	__le32 creator_id;
	__le32 creator_access;
	__le32 receiver_cnt;
	__le32 flags;
	__le32 nonce;
	__le32 block_cnt;
	u8 label[RPMI_TEE_PARCEL_LABEL_LEN];
	__le32 data[];
};

struct rpmi_tee_mem_parcel_create_resp {
	__le32 status;
	__le32 mem_parcel_id;
};

/* MEM_PARCEL_RECLAIM request (Table 206) / response (Table 207). */
struct rpmi_tee_mem_parcel_reclaim_req {
	__le32 mem_parcel_id;
};

struct rpmi_tee_mem_parcel_reclaim_resp {
	__le32 status;
	__le32 flags;
};

#endif /* __OPTEE_RISCV_H */
