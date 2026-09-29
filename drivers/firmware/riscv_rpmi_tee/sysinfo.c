// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * RPMI TEE system-information descriptor table parsing
 */

#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "sysinfo.h"

struct rpmi_tee_sysinfo_table {
	const u8 *data;
	u32 count;
	u16 desc_size;
	bool present;
};

/**
 * struct rpmi_tee_sysinfo - Validated SYSINFO descriptor-table state
 * @data: Start of the complete SYSINFO response buffer.
 * @len: Size of @data in bytes.
 * @tables: Table views indexed by &enum rpmi_tee_sysinfo_table_type.
 *
 * Each table view is populated only after the header, directory, table
 * range, and descriptor size have been validated.
 */
struct rpmi_tee_sysinfo {
	const u8 *data;
	size_t len;
	struct rpmi_tee_sysinfo_table tables[RPMI_TEE_SYSINFO_TABLE_MAX];
};

/* Assign table record @i in @t to a typed pointer @ptr. */
#define rpmi_tee_sysinfo_entry_at(t, i, ptr)			\
	do {							\
		typeof(t) table = (t);				\
		(ptr) = (typeof(ptr))(table->data +		\
			(size_t)(i) * table->desc_size);	\
	} while (0)

/**
 * rpmi_tee_sysinfo_buffer_range() - Validate a serialized SYSINFO range
 * @total: Total SYSINFO buffer size in bytes.
 * @offset: Byte offset of the first record.
 * @count: Number of records.
 * @size: Size of one record in bytes.
 * @start: Optional returned byte offset of the range.
 *
 * Check that @count records of @size bytes beginning at @offset neither
 * overflow nor extend beyond @total. If non-NULL, @start receives the byte
 * offset of the validated range.
 *
 * Return: 0 on success or -EINVAL if the range is invalid.
 */
static int rpmi_tee_sysinfo_buffer_range(size_t total, u32 offset, u32 count,
					 u16 size, size_t *start)
{
	size_t bytes, end;

	if (check_mul_overflow((size_t)count, (size_t)size, &bytes) ||
	    check_add_overflow((size_t)offset, bytes, &end) || end > total)
		return -EINVAL;

	if (start)
		*start = offset;

	return 0;
}

/* Validate a directory descriptor and record its table range in @info. */
static int rpmi_tee_sysinfo_get_table(struct rpmi_tee_sysinfo *info,
				      const struct rpmi_tee_sysinfo_table_desc *desc)
{
	u16 desc_size = get_unaligned_le16(&desc->desc_size);
	u32 offset = get_unaligned_le32(&desc->offset);
	u32 count = get_unaligned_le32(&desc->count);
	u16 type = get_unaligned_le16(&desc->type);
	struct rpmi_tee_sysinfo_table *table;
	size_t start;

	/* Validate table buffer. */
	if (rpmi_tee_sysinfo_buffer_range(info->len, offset, count, desc_size,
					  &start))
		return -EINVAL;

	switch (type) {
	case RPMI_TEE_SYSINFO_TABLE_ENDPOINT:
		if (desc_size < sizeof(struct rpmi_tee_sysinfo_endpoint))
			return -EINVAL;
		break;
	case RPMI_TEE_SYSINFO_TABLE_SERVICE:
		if (desc_size < sizeof(struct rpmi_tee_sysinfo_service))
			return -EINVAL;
		break;
	case RPMI_TEE_SYSINFO_TABLE_PARCEL:
		if (desc_size < sizeof(struct rpmi_tee_sysinfo_parcel))
			return -EINVAL;
		break;
	case RPMI_TEE_SYSINFO_TABLE_PARCEL_RECEIVER:
		if (desc_size < sizeof(struct rpmi_tee_sysinfo_parcel_receiver))
			return -EINVAL;
		break;
	case RPMI_TEE_SYSINFO_TABLE_MEMORY_BLOCK:
		if (desc_size < sizeof(struct rpmi_tee_sysinfo_memory_block))
			return -EINVAL;
		break;
	case RPMI_TEE_SYSINFO_TABLE_BLOB:
		/* BLOB table is defined as raw bytes. */
		if (desc_size != 1)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	table = &info->tables[type];
	if (table->present)
		return -EINVAL;

	table->data = info->data + start;
	table->count = count;
	table->desc_size = desc_size;
	table->present = true;

	return 0;
}

/* Validate the header and directory, then populate table views. */
static int rpmi_tee_sysinfo_init(struct rpmi_tee_sysinfo *info,
				  const void *data, size_t len)
{
	const struct rpmi_tee_sysinfo_header *header = data;
	u32 i, table_count, dir_off;
	u16 header_size, dir_size;

	memset(info, 0, sizeof(*info));

	if (len < sizeof(struct rpmi_tee_sysinfo_header))
		return -EINVAL;

	if (get_unaligned_le32(&header->magic) != RPMI_TEE_SYSINFO_MAGIC ||
	    get_unaligned_le16(&header->major) != RPMI_TEE_SYSINFO_VERSION_MAJOR ||
	    get_unaligned_le32(&header->total_size) != len)
		return -EINVAL;

	header_size = get_unaligned_le16(&header->header_size);
	dir_size = get_unaligned_le16(&header->table_desc_size);
	table_count = get_unaligned_le32(&header->table_count);
	dir_off = get_unaligned_le32(&header->table_dir_offset);

	if (header_size < sizeof(struct rpmi_tee_sysinfo_header) ||
	    dir_size < sizeof(struct rpmi_tee_sysinfo_table_desc) ||
	    /* Directory can not overlap with the header. */
	    dir_off < header_size)
		return -EINVAL;

	/* Validate directory buffer. */
	if (rpmi_tee_sysinfo_buffer_range(len, dir_off, table_count, dir_size,
					  NULL))
		return -EINVAL;

	info->data = data;
	info->len = len;
	for (i = 0; i < table_count; i++) {
		const struct rpmi_tee_sysinfo_table_desc *desc;
		int ret;

		desc = rpmi_tee_sysinfo_desc_at(header, i);
		ret = rpmi_tee_sysinfo_get_table(info, desc);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * rpmi_tee_sysinfo_table_check() - Check a table index range
 * @table: Validated table view.
 * @offset: First record index, or first byte index for a BLOB table.
 * @count: Number of records, or bytes for a BLOB table.
 *
 * An empty range @count = 0 is valid.
 * A non-empty range must fit wholly within @table.
 *
 * Return: %true if the range is valid or %false otherwise.
 */
static bool
rpmi_tee_sysinfo_table_check(const struct rpmi_tee_sysinfo_table *table,
			     u32 offset, u32 count)
{
	size_t end;

	if (!count)
		return true;
	/* For table->present = false or empty table, table->count is zero. */
	return !check_add_overflow((size_t)offset, (size_t)count, &end) &&
		end <= table->count;
}

/* Validate endpoint records and their service ranges. */
static int rpmi_tee_sysinfo_validate_endpoints(struct rpmi_tee_sysinfo *info,
					       bool require_single_ree,
					       u32 *self_ep_id)
{
	const struct rpmi_tee_sysinfo_table *service_table;
	const struct rpmi_tee_sysinfo_table *ep_table;
	const struct rpmi_tee_sysinfo_endpoint *ep;
	u32 ree_count = 0, ep_idx;

	ep_table = &info->tables[RPMI_TEE_SYSINFO_TABLE_ENDPOINT];
	service_table = &info->tables[RPMI_TEE_SYSINFO_TABLE_SERVICE];
	/* Endpoint table should exist and not empty; service table can be empty. */
	if (!ep_table->present || !ep_table->count || !service_table->present)
		return -EINVAL;

	for (ep_idx = 0; ep_idx < ep_table->count; ep_idx++) {
		rpmi_tee_sysinfo_entry_at(ep_table, ep_idx, ep);

		/* struct rpmi_tee_sysinfo_endpoint. */
		u32 ep_id = get_unaligned_le32(&ep->id);
		u32 parent_id = get_unaligned_le32(&ep->parent_id);
		u32 ep_flags = get_unaligned_le32(&ep->flags);
		u32 service_first = get_unaligned_le32(&ep->service_first);
		u32 service_range_count =
			get_unaligned_le32(&ep->service_count);

		bool is_physical =
			ep_flags & RPMI_TEE_SYSINFO_ENDPOINT_F_PHYSICAL;
		bool is_ree = ep_flags & RPMI_TEE_SYSINFO_ENDPOINT_F_REE;
		/* Require exactly one endpoint location and security role. */
		if (is_physical ==
			    !!(ep_flags & RPMI_TEE_SYSINFO_ENDPOINT_F_PROXIED) ||
		    is_ree == !!(ep_flags & RPMI_TEE_SYSINFO_ENDPOINT_F_TEE) ||
		    ep_flags & ~RPMI_TEE_SYSINFO_ENDPOINT_F_MASK)
			return -EINVAL;

		if (!rpmi_tee_sysinfo_table_check(service_table, service_first,
						  service_range_count))
			return -EINVAL;

		if (is_physical) {
			if (parent_id != RPMI_TEE_SYSINFO_ENDPOINT_NO_PARENT)
				return -EINVAL;

			if (is_ree) {
				ree_count++;
				if (self_ep_id)
					*self_ep_id = ep_id;
			}
		}
	}

	if (require_single_ree && ree_count != 1)
		return -EINVAL;

	return 0;
}

/**
 * rpmi_tee_sysinfo_parse_self() - Parse a Self SYSINFO table
 * @data: SYSINFO response buffer.
 * @len: Size of @data in bytes.
 * @self_ep_id: Returned local REE endpoint identifier.
 *
 * Return: 0 on success or a negative error code.
 */
int rpmi_tee_sysinfo_parse_self(const void *data, size_t len, u32 *self_ep_id)
{
	struct rpmi_tee_sysinfo info;
	int ret;

	if (!self_ep_id)
		return -EINVAL;

	ret = rpmi_tee_sysinfo_init(&info, data, len);
	if (ret)
		return ret;
	/* Expect single endpoint in a self SYSINFO response. */
	if (info.tables[RPMI_TEE_SYSINFO_TABLE_ENDPOINT].count != 1)
		return -EINVAL;

	return rpmi_tee_sysinfo_validate_endpoints(&info, true, self_ep_id);
}

/**
 * rpmi_tee_sysinfo_parse_system() - Parse a Whole-system SYSINFO table
 * @data: SYSINFO response buffer.
 * @len: Size of @data in bytes.
 * @self_ep_id: Local REE endpoint identifier from the Self table.
 * @system: Caller-provided discovery-result storage and returned counts.
 *
 * The parser records the number of required endpoint and service entries in
 * @system. If either caller-provided array is too small, it fills the entries
 * that fit, returns -ENOSPC, and reports the required counts. The caller may
 * then allocate the reported capacities and call this function again.
 *
 * Return: 0 on success, -ENOSPC if an output array is too small, or a
 * negative error code.
 */
int rpmi_tee_sysinfo_parse_system(const void *data, size_t len, u32 self_ep_id,
				  struct rpmi_tee_sysinfo_system *system)
{
	const struct rpmi_tee_sysinfo_table *service_table;
	const struct rpmi_tee_sysinfo_table *ep_table;
	const struct rpmi_tee_sysinfo_endpoint *ep;
	size_t ep_count = 0, service_count = 0;
	struct rpmi_tee_sysinfo info;
	bool self_ep_found = false;
	u32 ep_idx, service_idx;
	int ret;

	if ((system->ep_capacity && !system->eps) ||
	    (system->service_capacity && !system->services))
		return -EINVAL;

	ret = rpmi_tee_sysinfo_init(&info, data, len);
	if (ret)
		return ret;

	ret = rpmi_tee_sysinfo_validate_endpoints(&info, false, NULL);
	if (ret)
		return ret;

	ep_table = &info->tables[RPMI_TEE_SYSINFO_TABLE_ENDPOINT];
	service_table = &info->tables[RPMI_TEE_SYSINFO_TABLE_SERVICE];

	for (ep_idx = 0; ep_idx < ep_table->count; ep_idx++) {
		rpmi_tee_sysinfo_entry_at(ep_table, ep_idx, ep);

		/* struct rpmi_tee_sysinfo_endpoint. */
		u32 ep_flags = get_unaligned_le32(&ep->flags);
		u32 ep_id = get_unaligned_le32(&ep->id);
		u32 service_first = get_unaligned_le32(&ep->service_first);
		u32 service_range_count =
			get_unaligned_le32(&ep->service_count);

		/* Make sure self_ep_id exists in the list of endpoints. */
		if ((ep_flags & (RPMI_TEE_SYSINFO_ENDPOINT_F_PHYSICAL |
			      RPMI_TEE_SYSINFO_ENDPOINT_F_REE)) ==
		    (RPMI_TEE_SYSINFO_ENDPOINT_F_PHYSICAL |
		     RPMI_TEE_SYSINFO_ENDPOINT_F_REE) && ep_id == self_ep_id)
			self_ep_found = true;

		if (!(ep_flags & RPMI_TEE_SYSINFO_ENDPOINT_F_PHYSICAL) ||
		    !(ep_flags & RPMI_TEE_SYSINFO_ENDPOINT_F_TEE))
			continue;

		if (ep_count < system->ep_capacity)
			system->eps[ep_count].endpoint_id = ep_id;

		ep_count++;

		/* Extract per-endpoint services. */
		for (service_idx = service_first;
		     service_idx < service_first + service_range_count;
		     service_idx++) {
			const struct rpmi_tee_sysinfo_service *service;

			if (service_count < system->service_capacity) {
				rpmi_tee_sysinfo_entry_at(service_table,
							  service_idx, service);
				system->services[service_count].endpoint_id = ep_id;
				import_uuid(&system->services[service_count].uuid,
					    service->uuid);
			}

			if (check_add_overflow(service_count, 1, &service_count))
				return -EOVERFLOW;
		}
	}

	system->ep_count = ep_count;
	system->service_count = service_count;

	if (!self_ep_found)
		return -EINVAL;

	return ep_count > system->ep_capacity ||
	       service_count > system->service_capacity ? -ENOSPC : 0;
}
