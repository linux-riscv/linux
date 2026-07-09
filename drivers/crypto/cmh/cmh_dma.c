// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- DMA Operations
 *
 * Implements the cmh_dma.h interface using the kernel DMA API
 * (dma_map_single, dma_alloc_coherent, etc.).
 *
 * Scatterlist linearization rationale
 * ------------------------------------
 * The eSW firmware supports SCATTERGATHER commands for all core
 * types (AES_CMD_SCATTERGATHER, SM4_CMD_SCATTERGATHER,
 * CCP_CMD_SCATTERGATHER, HC_CMD_GATHER), using a proprietary
 * linked-list-item (LLI) descriptor chain format.  The hash driver
 * already uses this via cmh_dma_build_sg() + HC_CMD_GATHER.
 *
 * For symmetric cipher and AEAD commands, the LKM currently
 * linearizes scatterlist input into contiguous bounce buffers via
 * scatterwalk_map_and_copy() rather than building LLI chains from
 * kernel scatterlists.  This is a deliberate first-submission
 * simplification with a concrete technical justification:
 *
 *   - The hash SG path is unidirectional (DMA_TO_DEVICE gather only).
 *     Skcipher and AEAD require bidirectional handling: separate src
 *     and dst scatterlists (which may alias for in-place operations),
 *     plus AAD and authentication tag regions with distinct DMA
 *     directions and alignment constraints.
 *   - The CMH LLI format requires 64-byte aligned descriptor chain
 *     pointers (the .lli field) with 32-bit length fields.  This
 *     alignment is automatically satisfied by dma_alloc_coherent()
 *     for the descriptor array; data buffer addresses have no
 *     hardware alignment requirement.  Kernel SG entries have no
 *     alignment guarantee for data, so direct SG-to-LLI translation
 *     requires per-segment validation, potential splitting at
 *     descriptor boundaries, and separate chains for src/dst/AAD --
 *     substantially more complex than the unidirectional hash
 *     gather case.
 *   - Each skcipher/AEAD driver caps linearization at
 *     CMH_AES_MAX_CRYPTLEN / CMH_SM4_MAX_CRYPTLEN (32 MiB).
 *     Requests exceeding this cap are rejected with -EINVAL.
 *     In practice, crypto API callers (dm-crypt, IPsec, kernel TLS)
 *     send page-sized or smaller buffers, so the bounce allocation
 *     is typically <= PAGE_SIZE and succeeds even under GFP_ATOMIC.
 *
 * A shared SG-to-LLI adapter handling bidirectional mappings,
 * alignment splitting, and in-place src==dst detection for the
 * skcipher/AEAD/MAC paths is planned as a follow-up series once the
 * core driver is accepted.
 *
 * This linearization pattern is consistent with other upstream HW
 * crypto drivers that use bounce buffers in their initial
 * submissions (e.g. ccree, sa2ul, omap-aes).
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/overflow.h>
#include <linux/string.h>

#include "cmh_dma.h"

/* Module-global device pointer, set in cmh_dma_init() */
static struct device *cmh_device;

/**
 * cmh_dma_init() - Initialize the standard DMA backend
 * @pdev: Platform device providing the struct device for DMA ops
 *
 * Stores the device pointer for use by all DMA wrapper functions.
 *
 * Return: 0 (always succeeds for the standard backend).
 */
int cmh_dma_init(struct platform_device *pdev)
{
	cmh_device = &pdev->dev;
	return 0;
}

/**
 * cmh_dma_cleanup() - Tear down the standard DMA backend
 *
 * Clears the stored device pointer.
 */
void cmh_dma_cleanup(void)
{
	cmh_device = NULL;
}

/**
 * cmh_dev() - Return the platform device pointer
 *
 * Return: struct device pointer, or NULL outside probe/remove lifecycle.
 */
struct device *cmh_dev(void)
{
	return cmh_device;
}

/* -- Streaming DMA -------------------------------------------------------- */

/**
 * cmh_dma_map_single() - Map a kernel buffer for streaming DMA
 * @buf:  Kernel virtual address
 * @size: Buffer length in bytes
 * @dir:  DMA direction
 *
 * Return: DMA address, or a DMA_MAPPING_ERROR value on failure.
 */
dma_addr_t cmh_dma_map_single(void *buf, size_t size,
			      enum dma_data_direction dir)
{
	return dma_map_single(cmh_device, buf, size, dir);
}

/**
 * cmh_dma_unmap_single() - Unmap a streaming DMA buffer
 * @addr: DMA address returned by cmh_dma_map_single()
 * @size: Buffer length in bytes
 * @dir:  DMA direction (must match the map call)
 */
void cmh_dma_unmap_single(dma_addr_t addr, size_t size,
			  enum dma_data_direction dir)
{
	dma_unmap_single(cmh_device, addr, size, dir);
}

/**
 * cmh_dma_sync_for_cpu() - Sync a DMA buffer for CPU access
 * @addr: DMA address of the mapped buffer
 * @size: Region length in bytes
 * @dir:  DMA direction
 */
void cmh_dma_sync_for_cpu(dma_addr_t addr, size_t size,
			  enum dma_data_direction dir)
{
	dma_sync_single_for_cpu(cmh_device, addr, size, dir);
}

/**
 * cmh_dma_sync_for_device() - Sync a DMA buffer for device access
 * @addr: DMA address of the mapped buffer
 * @size: Region length in bytes
 * @dir:  DMA direction
 */
void cmh_dma_sync_for_device(dma_addr_t addr, size_t size,
			     enum dma_data_direction dir)
{
	dma_sync_single_for_device(cmh_device, addr, size, dir);
}

/**
 * cmh_dma_map_error() - Check whether a DMA mapping failed
 * @addr: DMA address to check
 *
 * Return: Non-zero if @addr indicates a mapping error.
 */
int cmh_dma_map_error(dma_addr_t addr)
{
	return dma_mapping_error(cmh_device, addr);
}

/* -- Coherent DMA --------------------------------------------------------- */

/**
 * cmh_dma_alloc() - Allocate coherent DMA memory
 * @size:   Allocation size in bytes
 * @handle: Output DMA address
 * @gfp:    GFP allocation flags
 *
 * Return: Kernel virtual address, or NULL on failure.
 */
void *cmh_dma_alloc(size_t size, dma_addr_t *handle, gfp_t gfp)
{
	return dma_alloc_coherent(cmh_device, size, handle, gfp);
}

/**
 * cmh_dma_free() - Free coherent DMA memory
 * @size:   Allocation size (must match cmh_dma_alloc)
 * @virt:   Kernel virtual address
 * @handle: DMA address
 */
void cmh_dma_free(size_t size, void *virt, dma_addr_t handle)
{
	dma_free_coherent(cmh_device, size, virt, handle);
}

/* -- Buffer write helpers ------------------------------------------------- */

/**
 * cmh_dma_write() - Copy data into a DMA buffer
 * @dst: Destination (from cmh_dma_alloc)
 * @src: Source kernel buffer
 * @len: Byte count
 */
void cmh_dma_write(void *dst, const void *src, size_t len)
{
	memcpy(dst, src, len);
}

/**
 * cmh_dma_fence() - No-op on standard DMA API platforms (coherent)
 * @ptr: Unused -- present for interface compatibility
 */
void cmh_dma_fence(void *ptr)
{
	/* Standard DMA API: coherent memory, no cross-slave fence needed */
}

/**
 * cmh_dma_zero() - Zero a DMA buffer
 * @dst: Destination (from cmh_dma_alloc)
 * @len: Byte count
 */
void cmh_dma_zero(void *dst, size_t len)
{
	memset(dst, 0, len);
}

/**
 * cmh_dma_build_sg() - Build a scatter-gather DMA mapping
 * @bufs: Array of buffer descriptors to map
 * @count: Number of entries in @bufs
 * @gfp: GFP flags for memory allocation
 *
 * Allocates a streaming-DMA descriptor array and maps each buffer in @bufs
 * for DMA-to-device transfer, filling CMH eSW-format scatter-gather
 * descriptors with linked-list pointers.
 *
 * The descriptor array uses streaming DMA (kmalloc + dma_map_single) rather
 * than dma_alloc_coherent so that cmh_dma_free_sg() -- which calls
 * dma_unmap_single + kfree -- is safe from any context including BH-disabled
 * completion callbacks.
 *
 * Return: Pointer to the allocated cmh_sg_map on success, NULL on failure.
 */
struct cmh_sg_map *cmh_dma_build_sg(const struct cmh_dma_buf *bufs, u32 count,
				    gfp_t gfp)
{
	struct cmh_sg_map *sgm;
	u32 i;

	if (!count)
		return NULL;

	sgm = kzalloc(struct_size(sgm, bufs, count), gfp);
	if (!sgm)
		return NULL;

	sgm->count = count;
	sgm->items_size = array_size(count, sizeof(*sgm->items));
	if (sgm->items_size == SIZE_MAX)
		goto err_free_sgm;

	/*
	 * Allocate descriptor array with kmalloc and map for streaming DMA.
	 * We map first to obtain items_dma (needed for .lli pointers),
	 * then sync-for-cpu, fill descriptors, and sync-for-device.
	 */
	sgm->items = kzalloc(sgm->items_size, gfp);
	if (!sgm->items)
		goto err_free_sgm;

	sgm->items_dma = cmh_dma_map_single(sgm->items, sgm->items_size,
					    DMA_TO_DEVICE);
	if (cmh_dma_map_error(sgm->items_dma))
		goto err_free_items;

	/* Map each source buffer for device read */
	for (i = 0; i < count; i++) {
		dma_addr_t dma;

		if (!bufs[i].len)
			goto err_unmap;
		sgm->bufs[i].len = bufs[i].len;
		dma = cmh_dma_map_single(bufs[i].data, bufs[i].len,
					 DMA_TO_DEVICE);
		if (cmh_dma_map_error(dma))
			goto err_unmap;
		sgm->bufs[i].dma = dma;
	}

	/*
	 * Reclaim CPU ownership of the descriptor buffer.  After
	 * dma_map_single the device owns the mapping; we must call
	 * sync_for_cpu before writing regardless of direction.  The
	 * direction matches the original mapping (DMA_TO_DEVICE) --
	 * this tells the DMA layer which cache operations apply:
	 * invalidate so the CPU sees coherent data before we fill
	 * the SG descriptors and later sync_for_device.
	 */
	cmh_dma_sync_for_cpu(sgm->items_dma, sgm->items_size,
			     DMA_TO_DEVICE);

	/* Fill CMH eSW SG descriptors */
	for (i = 0; i < count; i++) {
		u64 lli_val;

		if (i + 1 < count)
			lli_val = (u64)(sgm->items_dma +
				(i + 1) * sizeof(*sgm->items));
		else
			lli_val = 0;

		sgm->items[i].lli = lli_val;
		sgm->items[i].src = (u64)sgm->bufs[i].dma;
		sgm->items[i].dst = 0;
		sgm->items[i].len = (u64)bufs[i].len;
	}

	/* Flush descriptor writes to device */
	cmh_dma_sync_for_device(sgm->items_dma, sgm->items_size,
				DMA_TO_DEVICE);

	return sgm;

err_unmap:
	while (i--)
		cmh_dma_unmap_single(sgm->bufs[i].dma,
				     sgm->bufs[i].len, DMA_TO_DEVICE);
	cmh_dma_unmap_single(sgm->items_dma, sgm->items_size,
			     DMA_TO_DEVICE);
err_free_items:
	kfree(sgm->items);
err_free_sgm:
	kfree(sgm);
	return NULL;
}

/**
 * cmh_dma_free_sg() - Unmap and free a scatter-gather mapping
 * @sgm: Scatter-gather mapping created by cmh_dma_build_sg(), or NULL
 *
 * Unmaps all DMA-mapped buffers, unmaps and frees the descriptor array,
 * and releases the cmh_sg_map structure.  Safe to call from any context
 * (including BH-disabled completion callbacks) because it uses only
 * dma_unmap_single + kfree -- no vunmap/dma_free_coherent.
 */
void cmh_dma_free_sg(struct cmh_sg_map *sgm)
{
	u32 i;

	if (!sgm)
		return;

	for (i = 0; i < sgm->count; i++)
		cmh_dma_unmap_single(sgm->bufs[i].dma,
				     sgm->bufs[i].len, DMA_TO_DEVICE);

	cmh_dma_unmap_single(sgm->items_dma, sgm->items_size,
			     DMA_TO_DEVICE);
	kfree(sgm->items);
	kfree(sgm);
}

/**
 * cmh_dma_orphan_free() - Orphan cleanup callback for abandoned DMA buffers
 * @data: Pointer to a struct cmh_dma_orphan describing the orphaned mapping
 *
 * Called by the transaction manager when a synchronous operation times out
 * and the caller has already returned.  Unmaps the DMA buffer and frees
 * the backing memory and the orphan descriptor itself.
 */
void cmh_dma_orphan_free(void *data)
{
	struct cmh_dma_orphan *o = data;

	cmh_dma_unmap_single(o->addr, o->len, o->dir);
	kfree_sensitive(o->buf);
	kfree(o);
}
