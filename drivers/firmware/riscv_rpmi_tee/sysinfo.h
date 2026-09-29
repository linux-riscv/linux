/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RISC_V_RPMI_TEE_SYSINFO_H__
#define __RISC_V_RPMI_TEE_SYSINFO_H__

#include <linux/bitops.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <linux/unaligned.h>
#include <linux/uuid.h>

/* RPMI_TEE_FEATURE_SYSINFO_FORMAT. */
#define RPMI_TEE_SYSINFO_FORMAT_CBOR  BIT(31)	/* CBOR format. */
#define RPMI_TEE_SYSINFO_FORMAT_TABLE BIT(30)	/* Descriptor-table format. */

/* "SYSINFO descriptor-table format". */

#define RPMI_TEE_SYSINFO_MAGIC 0x49535452	/* Table magic ("RTSI"). */
#define RPMI_TEE_SYSINFO_VERSION_MAJOR 1	/* Supported major version. */

/**
 * struct rpmi_tee_sysinfo_header - SYSINFO descriptor-table header
 * @magic: RPMI_TEE_SYSINFO_MAGIC.
 * @major: Major format version.
 * @minor: Minor format version.
 * @header_size: Header size, including compatible extensions.
 * @table_desc_size: Size of one table-directory descriptor.
 * @total_size: Total response size in bytes.
 * @table_count: Number of table-directory descriptors.
 * @table_dir_offset: Byte offset of the table directory.
 * @flags: Ignored by version 1 Linux.
 * @reserved: Ignored by version 1 Linux.
 */
struct rpmi_tee_sysinfo_header {
	__le32 magic;
	__le16 major;
	__le16 minor;
	__le16 header_size;
	__le16 table_desc_size;
	__le32 total_size;
	__le32 table_count;
	__le32 table_dir_offset;
	__le32 flags;
	__le32 reserved;
} __packed;

enum rpmi_tee_sysinfo_table_type {
	RPMI_TEE_SYSINFO_TABLE_ENDPOINT = 0,	/* Endpoint records. */
	RPMI_TEE_SYSINFO_TABLE_SERVICE,		/* Service UUID records. */
	RPMI_TEE_SYSINFO_TABLE_PARCEL,		/* Memory parcel records. */
	RPMI_TEE_SYSINFO_TABLE_PARCEL_RECEIVER,	/* Parcel receiver records. */
	RPMI_TEE_SYSINFO_TABLE_MEMORY_BLOCK,	/* Memory block records. */
	RPMI_TEE_SYSINFO_TABLE_BLOB,		/* Arbitrary byte data. */
	RPMI_TEE_SYSINFO_TABLE_MAX,		/* One past the last table type. */
};

/**
 * struct rpmi_tee_sysinfo_table_desc - SYSINFO table-directory descriptor
 * @type: Table type from &enum rpmi_tee_sysinfo_table_type.
 * @desc_size: Size of one record in this table.
 * @count: Number of records in the table.
 * @offset: Byte offset of the first record.
 * @flags: Ignored by version 1 Linux.
 */
struct rpmi_tee_sysinfo_table_desc {
	__le16 type;
	__le16 desc_size;
	__le32 count;
	__le32 offset;
	__le32 flags;
} __packed;

/**
 * rpmi_tee_sysinfo_desc_at() - Get a table-directory descriptor
 * @header: SYSINFO response header at the start of the response buffer.
 * @index: Table-directory descriptor index.
 *
 * The caller must validate the table-directory range and @index before using
 * the returned descriptor.
 *
 * Return: Pointer to the descriptor's known prefix.
 */
static inline const struct rpmi_tee_sysinfo_table_desc *
rpmi_tee_sysinfo_desc_at(const struct rpmi_tee_sysinfo_header *header,
			 u32 index)
{
	u32 offset = get_unaligned_le32(&header->table_dir_offset);
	u16 stride = get_unaligned_le16(&header->table_desc_size);

	return (const void *)((const u8 *)header + offset +
			      (size_t)index * stride);
}

/* Records. */

#define RPMI_TEE_SYSINFO_ENDPOINT_NO_PARENT	U32_MAX /* No parent endpoint. */

#define RPMI_TEE_SYSINFO_ENDPOINT_F_PHYSICAL	BIT(0) /* Physical endpoint. */
#define RPMI_TEE_SYSINFO_ENDPOINT_F_PROXIED	BIT(1) /* Proxied endpoint. */
#define RPMI_TEE_SYSINFO_ENDPOINT_F_REE		BIT(2) /* REE endpoint. */
#define RPMI_TEE_SYSINFO_ENDPOINT_F_TEE		BIT(3) /* TEE endpoint. */
#define RPMI_TEE_SYSINFO_ENDPOINT_F_PERSISTENT	BIT(4) /* Persistent endpoint. */
#define RPMI_TEE_SYSINFO_ENDPOINT_F_MASK		\
	(RPMI_TEE_SYSINFO_ENDPOINT_F_PHYSICAL | \
	 RPMI_TEE_SYSINFO_ENDPOINT_F_PROXIED | \
	 RPMI_TEE_SYSINFO_ENDPOINT_F_REE | \
	 RPMI_TEE_SYSINFO_ENDPOINT_F_TEE | \
	 RPMI_TEE_SYSINFO_ENDPOINT_F_PERSISTENT)

/**
 * struct rpmi_tee_sysinfo_endpoint - Endpoint table record
 * @id: Endpoint identifier.
 * @parent_id: Parent endpoint identifier, if proxied.
 * @flags: RPMI_TEE_SYSINFO_ENDPOINT_F_* flags.
 * @service_first: First service record owned by the endpoint.
 * @service_count: Number of service records owned by the endpoint.
 * @parcel_first: First parcel record owned by the endpoint.
 * @parcel_count: Number of parcel records owned by the endpoint.
 * @name_offset: Byte offset of the endpoint name in the blob table.
 * @name_length: Endpoint name length in bytes.
 * @metadata_offset: Byte offset of endpoint metadata in the blob table.
 * @metadata_length: Endpoint metadata length in bytes.
 */
struct rpmi_tee_sysinfo_endpoint {
	__le32 id;
	__le32 parent_id;
	__le32 flags;
	__le32 service_first;
	__le32 service_count;
	__le32 parcel_first;
	__le32 parcel_count;
	__le32 name_offset;
	__le32 name_length;
	__le32 metadata_offset;
	__le32 metadata_length;
} __packed;

/**
 * struct rpmi_tee_sysinfo_service - Service table record
 * @uuid: Service UUID.
 */
struct rpmi_tee_sysinfo_service {
	u8 uuid[16];
} __packed;

/**
 * struct rpmi_tee_sysinfo_parcel - Memory parcel table record
 * @id: Parcel identifier.
 * @residual_access: Residual access permissions after relinquish.
 * @receiver_first: First parcel receiver record.
 * @receiver_count: Number of parcel receiver records.
 * @block_first: First memory block record.
 * @block_count: Number of memory block records.
 * @label_offset: Byte offset of the parcel label in the blob table.
 * @label_length: Parcel label length in bytes.
 * @flags: Parcel flags.
 * @reserved: Must be zero.
 */
struct rpmi_tee_sysinfo_parcel {
	__le32 id;
	__le32 residual_access;
	__le32 receiver_first;
	__le32 receiver_count;
	__le32 block_first;
	__le32 block_count;
	__le32 label_offset;
	__le32 label_length;
	__le32 flags;
	__le32 reserved;
} __packed;

/**
 * struct rpmi_tee_sysinfo_parcel_receiver - Parcel receiver table record
 * @endpoint_id: Receiver endpoint identifier.
 * @access: Access permissions granted to the receiver.
 * @flags: Receiver flags.
 * @reserved: Must be zero.
 */
struct rpmi_tee_sysinfo_parcel_receiver {
	__le32 endpoint_id;
	__le32 access;
	__le32 flags;
	__le32 reserved;
} __packed;

/**
 * struct rpmi_tee_sysinfo_memory_block - Memory block table record
 * @address: Physical base address.
 * @size: Block size in bytes.
 */
struct rpmi_tee_sysinfo_memory_block {
	__le64 address;
	__le64 size;
} __packed;

/**
 * struct rpmi_tee_sysinfo_service_info - Discovered TEE service
 * @endpoint_id: Owning TEE endpoint identifier.
 * @uuid: Service UUID.
 */
struct rpmi_tee_sysinfo_service_info {
	u32 endpoint_id;
	uuid_t uuid;
};

/**
 * struct rpmi_tee_sysinfo_endpoint_info - Discovered physical TEE endpoint
 * @endpoint_id: TEE endpoint identifier.
 */
struct rpmi_tee_sysinfo_endpoint_info {
	u32 endpoint_id;
};

/**
 * struct rpmi_tee_sysinfo_system - Parsed Whole-system discovery result
 * @eps: Caller-provided array of physical TEE endpoints.
 * @ep_capacity: Number of entries available in @eps.
 * @ep_count: Number of discovered physical TEE endpoints.
 * @services: Caller-provided array of TEE services.
 * @service_capacity: Number of entries available in @services.
 * @service_count: Number of discovered TEE services.
 *
 * The caller supplies storage and capacities. A sizing call with zero
 * capacities reports the required counts and returns -ENOSPC for a nonempty
 * result.
 */
struct rpmi_tee_sysinfo_system {
	struct rpmi_tee_sysinfo_endpoint_info *eps;
	size_t ep_capacity;
	size_t ep_count;
	struct rpmi_tee_sysinfo_service_info *services;
	size_t service_capacity;
	size_t service_count;
};

int rpmi_tee_sysinfo_parse_self(const void *data, size_t len, u32 *self_ep_id);
int rpmi_tee_sysinfo_parse_system(const void *data, size_t len,
				  u32 self_ep_id,
				  struct rpmi_tee_sysinfo_system *system);

#endif /* __RISC_V_RPMI_TEE_SYSINFO_H__ */
