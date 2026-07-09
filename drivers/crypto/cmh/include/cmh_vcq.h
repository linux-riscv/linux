/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- VCQ (Virtual Command Queue) Definitions
 *
 * Kernel-side definitions for the CMH VCQ and DMA scatter-gather ABI,
 * so the LKM can build VCQs without depending on CMH eSW headers.
 *
 * All constants and layouts are derived from the CMH eSW ABI.
 *
 * Per-core command definitions live in their own ABI headers (cmh_hc_abi.h,
 * cmh_aes_abi.h, etc.) and are included here to form the hwc_cmd union.
 */

#ifndef CMH_VCQ_H
#define CMH_VCQ_H

#include <linux/types.h>
#include <linux/build_bug.h>
#include <linux/string.h>
#include <linux/bits.h>

#include "cmh_hc_abi.h"
#include "cmh_sm3_abi.h"
#include "cmh_drbg_abi.h"
#include "cmh_sys_abi.h"
#include "cmh_kic_abi.h"
#include "cmh_aes_abi.h"
#include "cmh_sm4_abi.h"
#include "cmh_ccp_abi.h"
#include "cmh_pke_abi.h"
#include "cmh_qse_abi.h"
#include "cmh_hcq_abi.h"
#include "cmh_eac_abi.h"

/* VCQ Magic Numbers */

#define VCQ_HDR_MAGIC           0x01514356U  /* 'V' 'C' 'Q' 0x01 */
#define VCQ_CMD_MAGIC           0x01444D43U  /* 'C' 'M' 'D' 0x01 */

/* VCQ Command ID Encoding */

#define VCQ_CMD_MASK            0x000000FFU
#define VCQ_SPAN_MASK           0x0000FF00U
#define VCQ_FLAG_MASK           0x00FF0000U
#define VCQ_CORE_MASK           0xFF000000U

#define VCQ_CMD_ID(core, flags, span, cmd) \
	(((u32)(core) << 24) | ((flags) & VCQ_FLAG_MASK) | \
	 (((u32)(span) << 8) & VCQ_SPAN_MASK) | ((cmd) & VCQ_CMD_MASK))

/* Core IDs (per CMH hardware specification) */

#define CORE_ID_SYS             0x00U
#define CORE_ID_DMA             0x01U
#define CORE_ID_HC              0x02U
#define CORE_ID_AES             0x03U
#define CORE_ID_SM4             0x04U
#define CORE_ID_SM3             0x05U
#define CORE_ID_XC              0x07U
#define CORE_ID_HCQ             0x08U
#define CORE_ID_QSE             0x09U
#define CORE_ID_PKE             0x0AU
#define CORE_ID_TIC             0x0BU
#define CORE_ID_KIC             0x0CU
#define CORE_ID_MPU             0x0EU
#define CORE_ID_DRBG            0x0FU
#define CORE_ID_EMC             0x11U
#define CORE_ID_CCP             0x18U
#define CORE_ID_EAC             0x1EU
#define CORE_ID_NUM             0x1FU  /* eSW g_drvs[] array size sentinel */
#define CORE_ID_MAX             0xFFU  /* VCQ encoding limit (8-bit field) */

/**
 * enum cmh_core_type - Logical core type for multi-instance dispatch
 * @CMH_CORE_HC:         Hash / HMAC / CSHAKE / KMAC (CORE_ID_HC)
 * @CMH_CORE_AES:        AES (CORE_ID_AES)
 * @CMH_CORE_SM4:        SM4 (CORE_ID_SM4)
 * @CMH_CORE_SM3:        SM3 (CORE_ID_SM3)
 * @CMH_CORE_CCP:        ChaCha20 / Poly1305 (CORE_ID_CCP)
 * @CMH_CORE_PKE:        RSA / ECDSA / ECDH / EdDSA / SM2 (CORE_ID_PKE)
 * @CMH_CORE_QSE:        ML-KEM / ML-DSA (CORE_ID_QSE)
 * @CMH_CORE_HCQ:        SLH-DSA / LMS / XMSS (CORE_ID_HCQ)
 * @CMH_NUM_CORE_TYPES:  Number of core types (array sizing sentinel)
 *
 * Algorithm drivers use this enum (not raw CORE_ID_* constants) for
 * MBX selection and VCQ dispatch.  Each value indexes into a config
 * table that maps to one or more (core_id, mbx) pairs.
 *
 * Raw CORE_ID_* defines remain for:
 *   - SYS_TYPE_SET() key-type tags in datastore operations
 *   - DT child node ``reg`` values (hardware core identity for config lookup)
 *   - Singleton system cores (SYS, KIC, DRBG, EAC) not in this enum
 */
enum cmh_core_type {
	CMH_CORE_HC = 0,
	CMH_CORE_AES,
	CMH_CORE_SM4,
	CMH_CORE_SM3,
	CMH_CORE_CCP,
	CMH_CORE_PKE,
	CMH_CORE_QSE,
	CMH_CORE_HCQ,
	CMH_NUM_CORE_TYPES
};

/**
 * struct core_dispatch - VCQ dispatch target returned by core selection
 * @core_id: Hardware core ID to encode in VCQ_CMD_ID()
 * @mbx_idx: Mailbox index to submit the VCQ to
 */
struct core_dispatch {
	u32 core_id;
	s32 mbx_idx;
};

/* Common VCQ Command (per CMH VCQ ABI) */

#define VCQ_CMD_FLUSH           0xFFU

/**
 * struct vcq_hdr - VCQ header occupying the first slot of every VCQ
 * @cmds: Total number of commands including the header itself
 * @rsvd: Reserved -- used internally by CMH eSW firmware
 */
struct vcq_hdr {
	u32 cmds;
	u32 rsvd[13];
};

/* DMA Scatter-Gather Item (per CMH DMAC hardware specification) */

/**
 * struct dma_scattergather_item - DMA scatter-gather descriptor node
 * @lli: Next descriptor address (0 = end of list)
 * @src: Source address for input particle
 * @dst: Destination address for output particle
 * @len: Particle length (low 32 bits used by hardware)
 *
 * Linked-list node walked by the DMAC hardware.  @lli chains to the
 * next item or is zero for end-of-list.
 */
struct dma_scattergather_item {
	u64 lli;
	u64 src;
	u64 dst;
	u64 len;
};

/* Unified HWC Command Union */
/*
 * Each per-core ABI header defines a union <core>_cmd.
 * Add new cores here as they are implemented.
 */

union hwc_cmd {
	struct vcq_hdr          hdr;
	union hc_cmd            hc;
	union sm3_cmd           sm3;
	union drbg_cmd          drbg;
	union sys_cmd           sys;
	union kic_cmd           kic;
	union aes_cmd           aes;
	union sm4_cmd           sm4;
	union ccp_cmd           ccp;
	union pke_cmd           pke;
	union qse_cmd           qse;
	union hcq_cmd           hcq;
	union eac_cmd           eac;
};

/**
 * struct vcq_cmd - Single VCQ command entry (always 64 bytes)
 * @magic: VCQ_HDR_MAGIC for the header slot, VCQ_CMD_MAGIC for commands
 * @id:    Encoded command ID built via VCQ_CMD_ID(core, flags, span, cmd)
 * @hwc:   Per-core command payload union
 */
struct vcq_cmd {
	u32 magic;
	u32 id;
	union hwc_cmd hwc;
};

static_assert(sizeof(struct vcq_cmd) == 64,
	      "struct vcq_cmd must be exactly 64 bytes (one VCQ slot)");

/**
 * vcq_set_header() - Write the standard VCQ header at slot[0]
 * @slot:       Pointer to the first VCQ slot
 * @total_cmds: Total number of commands including the header
 */
static inline void vcq_set_header(struct vcq_cmd *slot, u32 total_cmds)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_HDR_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_RUN);
	slot->hwc.hdr.cmds = total_cmds;
}

/* VCQ Command Limits */

#define MIN_VCQ_CMDS            2U   /* header + at least one command */
#define MAX_VCQ_CMDS            15U  /* including the header */
#define MAX_VCQ_SIZE            (MAX_VCQ_CMDS * sizeof(struct vcq_cmd))

/**
 * vcq_add_inline_data() - Pack inline data into consecutive VCQ slots
 * @slot:     Pointer to the command slot preceding the inline data
 * @data:     Source data to copy into subsequent slots
 * @data_len: Length of @data in bytes
 *
 * Appends data starting at slot+1 and updates the span field in
 * slot->id.  The caller must ensure enough slots are reserved.
 *
 * Return: Total number of slots consumed (1 + inline slots).
 */
static inline u32 vcq_add_inline_data(struct vcq_cmd *slot,
				      const void *data, u32 data_len)
{
	u32 inline_slots, total_span;

	if (!data_len)
		return 1;

	inline_slots = (data_len + sizeof(struct vcq_cmd) - 1) /
		       sizeof(struct vcq_cmd);
	total_span = 1 + inline_slots;

	/* Zero the inline slots, then copy data */
	memset(slot + 1, 0, inline_slots * sizeof(struct vcq_cmd));
	memcpy(slot + 1, data, data_len);

	/* Update span in the command's id field */
	slot->id = (slot->id & ~VCQ_SPAN_MASK) |
		   (((u32)total_span << 8) & VCQ_SPAN_MASK);

	return total_span;
}

/**
 * vcq_add_flush() - Build a generic VCQ_CMD_FLUSH command
 * @slot:    Pointer to the VCQ slot to populate
 * @core_id: Hardware core ID for the flush command
 */
static inline void vcq_add_flush(struct vcq_cmd *slot, u32 core_id)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, VCQ_CMD_FLUSH);
}

/* Shared HC VCQ Builders -- used by hash, hmac, cshake, kmac drivers */

static inline void vcq_add_hc_init(struct vcq_cmd *slot, u32 core_id,
				   u32 algo)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_INIT);
	slot->hwc.hc.cmd_init.algo = algo;
}

static inline void vcq_add_hc_final(struct vcq_cmd *slot, u32 core_id,
				    u64 digest_phys, u32 outlen)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_FINAL);
	slot->hwc.hc.cmd_final.digest = digest_phys;
	slot->hwc.hc.cmd_final.outlen = outlen;
}

static inline void vcq_add_hc_gather(struct vcq_cmd *slot, u32 core_id,
				     u64 lista_phys, u32 sgcmd)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1, HC_CMD_GATHER);
	slot->hwc.hc.cmd_gather.lista = lista_phys;
	slot->hwc.hc.cmd_gather.sgcmd = sgcmd;
}

#endif /* CMH_VCQ_H */
