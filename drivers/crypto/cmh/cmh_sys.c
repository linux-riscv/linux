// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SYS Core VCQ Builders
 *
 * VCQ builder functions for SYS core datastore commands.  Each function
 * populates a single vcq_cmd slot.  Callers (cmh_mgmt.c, cmh_key.c)
 * assemble complete VCQs by combining header + command(s) + flush,
 * then submit via cmh_tm_submit_sync().
 *
 * Hardware-required datastore semantics
 * --------------------------------------
 * The commands below (NEW, WRITE, DATA, FIND, DELETE, FLUSH) are
 * direct mappings of the eSW firmware SYS core command set.  The
 * eSW maintains per-mailbox datastore namespaces with two object
 * classes:
 *
 *   SYS_REF_TEMP   -- Temporary objects.  Lifetime is scoped to the
 *                      current mailbox slot; reclaimed automatically
 *                      when the slot is reused or on explicit FLUSH.
 *                      Used for raw-key provisioning on every VCQ.
 *
 *   SYS_REF_PERSIST -- Persistent objects.  Survive across slots;
 *                      require explicit DELETE to reclaim.  Identified
 *                      by a 64-bit Content ID (CID) and resolved to
 *                      a per-MBX ref via SYS_CMD_FIND.
 *
 * These semantics are hardware requirements, not driver policy.
 * The per-MBX temp-stack and per-MBX ref namespace are eSW firmware
 * design constraints that cannot be changed by the kernel driver.
 */

#include <linux/string.h>

#include "cmh_sys.h"

/**
 * vcq_add_sys_flush() - Build a SYS_FLUSH VCQ command
 * @slot: VCQ command slot to populate
 */
void vcq_add_sys_flush(struct vcq_cmd *slot)
{
	vcq_add_flush(slot, CORE_ID_SYS);
}

/**
 * vcq_add_sys_new() - Build a SYS_NEW VCQ command
 * @slot: VCQ command slot to populate
 * @cid: Content identifier for the new datastore object
 * @ref_dma: DMA address of the object reference buffer
 * @len: Length of the object data in bytes
 */
void vcq_add_sys_new(struct vcq_cmd *slot, u64 cid, u64 ref_dma, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_NEW);
	slot->hwc.sys.cmd_new.cid = cid;
	slot->hwc.sys.cmd_new.ref = ref_dma;
	slot->hwc.sys.cmd_new.len = len;
}

/**
 * vcq_add_sys_write() - Build a SYS_WRITE VCQ command
 * @slot: VCQ command slot to populate
 * @ref: Datastore object reference handle
 * @src_dma: DMA address of source data buffer
 * @wrap_key: Wrapping key reference (0 if none)
 * @len: Length of data to write in bytes
 * @sys_type: Datastore object type identifier
 */
void vcq_add_sys_write(struct vcq_cmd *slot, u64 ref, u64 src_dma,
		       u64 wrap_key, u32 len, u32 sys_type)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_WRITE);
	slot->hwc.sys.cmd_write.ref = ref;
	slot->hwc.sys.cmd_write.src = src_dma;
	slot->hwc.sys.cmd_write.key = wrap_key;
	slot->hwc.sys.cmd_write.len = len;
	slot->hwc.sys.cmd_write.type = sys_type;
}

/**
 * vcq_add_sys_read() - Build a SYS_READ VCQ command
 * @slot: VCQ command slot to populate
 * @ref: Datastore object reference handle
 * @dst_dma: DMA address of destination buffer
 * @wrap_key: Wrapping key reference (0 if none)
 * @len: Length of data to read in bytes
 */
void vcq_add_sys_read(struct vcq_cmd *slot, u64 ref, u64 dst_dma,
		      u64 wrap_key, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_READ);
	slot->hwc.sys.cmd_read.ref = ref;
	slot->hwc.sys.cmd_read.dst = dst_dma;
	slot->hwc.sys.cmd_read.key = wrap_key;
	slot->hwc.sys.cmd_read.len = len;
}

/**
 * vcq_add_sys_data() - Build a SYS_DATA VCQ command
 * @slot: VCQ command slot to populate
 * @ref: Datastore object reference handle
 * @dst_dma: DMA address of destination buffer
 * @len: Length of data section to read in bytes
 */
void vcq_add_sys_data(struct vcq_cmd *slot, u64 ref, u64 dst_dma, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_DATA);
	slot->hwc.sys.cmd_data.ref = ref;
	slot->hwc.sys.cmd_data.dst = dst_dma;
	slot->hwc.sys.cmd_data.len = len;
}

/**
 * vcq_add_sys_find() - Build a SYS_FIND VCQ command
 * @slot: VCQ command slot to populate
 * @cid: Content identifier to search for
 * @dst_dma: DMA address of destination buffer for result
 * @len: Length of destination buffer in bytes
 */
void vcq_add_sys_find(struct vcq_cmd *slot, u64 cid, u64 dst_dma, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_FIND);
	slot->hwc.sys.cmd_find.cid = cid;
	slot->hwc.sys.cmd_find.dst = dst_dma;
	slot->hwc.sys.cmd_find.len = len;
}

/**
 * vcq_add_sys_list() - Build a SYS_LIST VCQ command
 * @slot: VCQ command slot to populate
 * @ref: Datastore object reference for enumeration start
 * @dst_dma: DMA address of destination buffer for list
 * @len: Length of destination buffer in bytes
 */
void vcq_add_sys_list(struct vcq_cmd *slot, u64 ref, u64 dst_dma, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_LIST);
	slot->hwc.sys.cmd_list.ref = ref;
	slot->hwc.sys.cmd_list.dst = dst_dma;
	slot->hwc.sys.cmd_list.len = len;
}

/**
 * vcq_add_sys_grant() - Build a SYS_GRANT VCQ command
 * @slot: VCQ command slot to populate
 * @ref: Datastore object reference handle
 * @read: Read permission bitmask
 * @write: Write permission bitmask
 * @execute: Execute permission bitmask
 */
void vcq_add_sys_grant(struct vcq_cmd *slot, u64 ref, u64 read,
		       u64 write, u64 execute)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_GRANT);
	slot->hwc.sys.cmd_grant.ref = ref;
	slot->hwc.sys.cmd_grant.read = read;
	slot->hwc.sys.cmd_grant.write = write;
	slot->hwc.sys.cmd_grant.execute = execute;
}

/**
 * vcq_add_sys_export() - Build a SYS_EXPORT VCQ command
 * @slot: VCQ command slot to populate
 * @cid: Content identifier of object to export
 * @dst_dma: DMA address of destination buffer for wrapped blob
 * @wrap_key: Wrapping key reference for export
 * @len: Length of destination buffer in bytes
 */
void vcq_add_sys_export(struct vcq_cmd *slot, u64 cid, u64 dst_dma,
			u64 wrap_key, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_EXPORT);
	slot->hwc.sys.cmd_export.cid = cid;
	slot->hwc.sys.cmd_export.dst = dst_dma;
	slot->hwc.sys.cmd_export.key = wrap_key;
	slot->hwc.sys.cmd_export.len = len;
}

/**
 * vcq_add_sys_import() - Build a SYS_IMPORT VCQ command
 * @slot: VCQ command slot to populate
 * @src_dma: DMA address of wrapped datastore blob to import
 * @wrap_key: Wrapping key reference for unwrapping
 * @len: Length of wrapped blob in bytes
 */
void vcq_add_sys_import(struct vcq_cmd *slot, u64 src_dma,
			u64 wrap_key, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_SYS, 0, 1, SYS_CMD_IMPORT);
	slot->hwc.sys.cmd_import.src = src_dma;
	slot->hwc.sys.cmd_import.key = wrap_key;
	slot->hwc.sys.cmd_import.len = len;
}

/* -- KIC Core VCQ Builders --------------------- */

/**
 * vcq_add_kic_hkdf1() - Build a KIC HKDF-Expand VCQ command
 * @slot: VCQ command slot to populate
 * @dst: Datastore reference for derived key output
 * @base: Datastore reference for base key input
 * @label_dma: DMA address of HKDF label/info buffer
 * @key_len: Derived key length in bytes
 * @label_len: Length of label buffer in bytes
 * @type: Derived key datastore type
 */
void vcq_add_kic_hkdf1(struct vcq_cmd *slot, u64 dst, u64 base,
		       u64 label_dma, u32 key_len, u32 label_len, u32 type)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_KIC, 0, 1, KIC_CMD_HKDF1);
	slot->hwc.kic.cmd_hkdf1.dst = dst;
	slot->hwc.kic.cmd_hkdf1.base = base;
	slot->hwc.kic.cmd_hkdf1.label = label_dma;
	slot->hwc.kic.cmd_hkdf1.llen = label_len;
	slot->hwc.kic.cmd_hkdf1.len = key_len;
	slot->hwc.kic.cmd_hkdf1.type = type;
}

/**
 * vcq_add_kic_hkdf2() - Build a KIC HKDF-with-salt VCQ command
 * @slot: VCQ command slot to populate
 * @dst: Datastore reference for derived key output
 * @base: Datastore reference for base key input
 * @salt: Datastore reference for HKDF salt key
 * @label_dma: DMA address of HKDF label/info buffer
 * @key_len: Derived key length in bytes
 * @label_len: Length of label buffer in bytes
 * @type: Derived key datastore type
 */
void vcq_add_kic_hkdf2(struct vcq_cmd *slot, u64 dst, u64 base, u64 salt,
		       u64 label_dma, u32 key_len, u32 label_len, u32 type)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_KIC, 0, 1, KIC_CMD_HKDF2);
	slot->hwc.kic.cmd_hkdf2.dst = dst;
	slot->hwc.kic.cmd_hkdf2.base = base;
	slot->hwc.kic.cmd_hkdf2.salt = salt;
	slot->hwc.kic.cmd_hkdf2.label = label_dma;
	slot->hwc.kic.cmd_hkdf2.llen = label_len;
	slot->hwc.kic.cmd_hkdf2.len = key_len;
	slot->hwc.kic.cmd_hkdf2.type = type;
}

/**
 * vcq_add_kic_aes_cmac_kdf() - Build a KIC AES-CMAC KDF VCQ command
 * @slot: VCQ command slot to populate
 * @out_key: Datastore reference for derived key output
 * @base_key: Datastore reference for base key input
 * @label_dma: DMA address of KDF label buffer
 * @key_len: Derived key length in bytes
 * @label_len: Length of label buffer in bytes
 * @type: Derived key datastore type
 */
void vcq_add_kic_aes_cmac_kdf(struct vcq_cmd *slot, u64 out_key, u64 base_key,
			      u64 label_dma, u32 key_len, u32 label_len,
			      u32 type)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_KIC, 0, 1, KIC_CMD_AES_CMAC_KDF);
	slot->hwc.kic.cmd_aes_cmac_kdf.base_key = base_key;
	slot->hwc.kic.cmd_aes_cmac_kdf.out_key = out_key;
	slot->hwc.kic.cmd_aes_cmac_kdf.label = label_dma;
	slot->hwc.kic.cmd_aes_cmac_kdf.key_len = key_len;
	slot->hwc.kic.cmd_aes_cmac_kdf.label_len = label_len;
	slot->hwc.kic.cmd_aes_cmac_kdf.type = type;
}

/**
 * vcq_add_kic_dkek_derive() - Build a KIC DKEK derivation VCQ command
 * @slot: VCQ command slot to populate
 * @out_key: Datastore reference for derived DKEK output
 * @base_key: Datastore reference for base key input
 * @host_id: Host identifier for key binding
 * @metadata_dma: DMA address of derivation metadata buffer
 * @metadata_len: Length of metadata buffer in bytes
 */
void vcq_add_kic_dkek_derive(struct vcq_cmd *slot, u64 out_key, u64 base_key,
			     u32 host_id, u64 metadata_dma, u32 metadata_len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_KIC, 0, 1, KIC_CMD_DKEK_DERIVE);
	slot->hwc.kic.cmd_dkek_derive.base_key = base_key;
	slot->hwc.kic.cmd_dkek_derive.out_key = out_key;
	slot->hwc.kic.cmd_dkek_derive.host_id = host_id;
	slot->hwc.kic.cmd_dkek_derive.metadata = metadata_dma;
	slot->hwc.kic.cmd_dkek_derive.metadata_len = metadata_len;
}

/* -- DRBG Core VCQ Builders -------------------- */

/**
 * vcq_add_drbg_reset() - Build a DRBG reset VCQ command
 * @slot: VCQ command slot to populate
 *
 * Issues DRBG_CMD_RESET which clears the instantiated state, allowing
 * a subsequent CONFIG to proceed without a double-instantiate error.
 */
void vcq_add_drbg_reset(struct vcq_cmd *slot)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_DRBG, 0, 1, DRBG_CMD_RESET);
}

/**
 * vcq_add_drbg_config() - Build a DRBG configuration VCQ command
 * @slot: VCQ command slot to populate
 * @ratio: Entropy-to-output ratio
 * @strength: Security strength in bits
 */
void vcq_add_drbg_config(struct vcq_cmd *slot, u32 ratio, u32 strength)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_DRBG, 0, 1, DRBG_CMD_CONFIG);
	slot->hwc.drbg.cmd_config.entropy_ratio = ratio;
	slot->hwc.drbg.cmd_config.security_strength = strength;
}

/**
 * vcq_add_drbg_datastore() - Build a DRBG datastore setup VCQ command
 * @slot: VCQ command slot to populate
 * @ref: Datastore object reference handle
 * @len: Length of datastore allocation in bytes
 * @type: Datastore object type
 */
void vcq_add_drbg_datastore(struct vcq_cmd *slot, u64 ref, u32 len, u32 type)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_DRBG, 0, 1, DRBG_CMD_DATASTORE);
	slot->hwc.drbg.cmd_datastore.ref = ref;
	slot->hwc.drbg.cmd_datastore.len = len;
	slot->hwc.drbg.cmd_datastore.type = type;
}

/* -- EAC Core VCQ Builder ---------------------- */

/**
 * vcq_add_eac_read() - Build an EAC read VCQ command
 * @slot: VCQ command slot to populate
 * @dst_dma: DMA address of destination buffer
 * @len: Length of data to read in bytes
 */
void vcq_add_eac_read(struct vcq_cmd *slot, u64 dst_dma, u32 len)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(CORE_ID_EAC, 0, 1, EAC_CMD_READ);
	slot->hwc.eac.cmd_read.dst = dst_dma;
	slot->hwc.eac.cmd_read.len = len;
}
