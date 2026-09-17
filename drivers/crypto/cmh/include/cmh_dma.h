/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- DMA Interface
 *
 * Platform-independent DMA operations for the CMH crypto accelerator.
 * All functions are implemented in cmh_dma.c (standard kernel DMA API).
 *
 * Alternate backends may be linked in place of cmh_dma.c for
 * non-standard platforms.  Such backends must implement the same
 * symbol set and may use different allocation and mapping semantics
 * (e.g. pool-based alloc/free instead of address translation).
 */

#ifndef CMH_DMA_H
#define CMH_DMA_H

#include <linux/dma-mapping.h>
#include <linux/types.h>

#include "cmh_vcq.h"

struct platform_device;

/**
 * cmh_dma_init() - Initialize the DMA backend
 * @pdev: Platform device (provides struct device for DMA ops)
 *
 * Called early in .probe().  The standard backend stores the device
 * pointer; alternate backends may set up additional resources.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_dma_init(struct platform_device *pdev);

/**
 * cmh_dma_cleanup() - Tear down the DMA backend
 *
 * Called in .remove() and error paths.  Releases any resources
 * allocated by cmh_dma_init().
 */
void cmh_dma_cleanup(void);

/**
 * cmh_dev() - Global device accessor
 *
 * Returns the struct device * associated with the platform_driver instance.
 * Valid only between cmh_dma_init() and cmh_dma_cleanup().
 *
 * Return: Platform device pointer, or NULL outside lifecycle.
 */
struct device *cmh_dev(void);

/* Streaming DMA map / unmap (short-lived per-request buffers) */

dma_addr_t cmh_dma_map_single(void *buf, size_t size,
			      enum dma_data_direction dir);
void cmh_dma_unmap_single(dma_addr_t addr, size_t size,
			  enum dma_data_direction dir);

/*
 * Sync a DMA_FROM_DEVICE buffer so the CPU sees device-written data.
 *
 * Required before reading *buf when SWIOTLB bounce buffering is active
 * (e.g. arm64 without IOMMU): the device writes to the bounce buffer,
 * not the original allocation, so the CPU must sync before access.
 * On architectures without bounce buffers (e.g. rv64) this is a no-op.
 *
 * Call between cmh_tm_submit_sync() and the first CPU read of the buffer,
 * while the mapping is still live (before cmh_dma_unmap_single).
 */
void cmh_dma_sync_for_cpu(dma_addr_t addr, size_t size,
			  enum dma_data_direction dir);

/*
 * Sync a DMA_TO_DEVICE buffer so the device sees CPU-written data.
 *
 * Required after CPU writes to a mapped streaming buffer (e.g. SG
 * descriptor arrays that need items_dma for .lli pointer calculation
 * before content is written).  Must be called before the device reads.
 */
void cmh_dma_sync_for_device(dma_addr_t addr, size_t size,
			     enum dma_data_direction dir);

int cmh_dma_map_error(dma_addr_t addr);

/* Coherent DMA alloc / free (long-lived MBX queue buffers) */

void *cmh_dma_alloc(size_t size, dma_addr_t *handle, gfp_t gfp);
void cmh_dma_free(size_t size, void *virt, dma_addr_t handle);

/**
 * cmh_dma_write() - Copy data into a DMA-allocated buffer
 * @dst: Destination pointer (from cmh_dma_alloc)
 * @src: Source kernel buffer
 * @len: Number of bytes to copy
 *
 * Copies @len bytes from @src to @dst.  @dst must have been obtained
 * from cmh_dma_alloc().  Abstracted to allow platforms with non-standard
 * DMA buffer access semantics.
 */
void cmh_dma_write(void *dst, const void *src, size_t len);

/**
 * cmh_dma_fence() - Fence preceding writes to DMA-allocated memory
 * @ptr: Any pointer into the region that was written
 *
 * Ensures all preceding CPU writes to DMA memory are committed to the
 * target memory controller before subsequent MMIO register writes.
 *
 * Required on FPGA platforms where DMA memory and device control
 * registers reside on different AXI slaves -- a CPU-side wmb() only
 * orders store dispatch, not arrival at the target.  A read from the
 * DMA memory slave forces the memory controller to serialize behind
 * all preceding writes from this CPU before responding, guaranteeing
 * the data is committed before the doorbell register write is issued.
 *
 * On standard DMA API platforms (cache-coherent), this is a no-op.
 */
void cmh_dma_fence(void *ptr);

/**
 * cmh_dma_zero() - Zero a DMA-allocated buffer
 * @dst: Destination pointer (from cmh_dma_alloc)
 * @len: Number of bytes to zero
 */
void cmh_dma_zero(void *dst, size_t len);

/*
 * CMH eSW scatter-gather chain -- built with proper DMA mappings.
 *
 * The CMH eSW DMAC walks a linked list of dma_scattergather_item
 * descriptors.  Each .src is the DMA address of an input buffer;
 * each .lli is the DMA address of the next descriptor (0 = end).
 *
 * The descriptor array uses streaming DMA (kmalloc + dma_map_single)
 * so that cmh_dma_free_sg() is safe from any context -- including
 * BH-disabled completion callbacks where dma_free_coherent's
 * vunmap() path would crash on non-coherent architectures.
 */

/* Input descriptor for cmh_dma_build_sg() -- one per data buffer */
struct cmh_dma_buf {
	void *data;
	u32   len;
};

/* Opaque handle returned by cmh_dma_build_sg(); pass to cmh_dma_free_sg() */
struct cmh_sg_map {
	struct dma_scattergather_item *items;	/* CPU virtual address */
	dma_addr_t  items_dma;			/* DMA address (pass to GATHER cmd) */
	size_t      items_size;			/* allocation size */
	u32         count;
	struct {
		dma_addr_t dma;
		u32        len;
	} bufs[];				/* per-entry source DMA handles */
};

/**
 * cmh_dma_build_sg() - Build a DMA-mapped CMH eSW SG chain
 * @bufs: Array of kernel buffer descriptors (data pointer + length)
 * @count: Number of entries in @bufs (must be > 0; returns NULL for 0)
 * @gfp: Allocation flags (GFP_KERNEL or GFP_ATOMIC)
 *
 * Allocates a dma_scattergather_item chain using streaming DMA
 * (kmalloc + dma_map_single), DMA-maps each source buffer, and
 * links the descriptors.
 * The returned cmh_sg_map->items_dma is the address to pass to
 * vcq_add_hc_gather() (or any core's scatter-gather command).
 *
 * Caller contract:
 *   - Each bufs[i].data must point to DMA-mappable memory (kmalloc,
 *     page-allocated, or vmalloc with DMA support).  Stack buffers
 *     are NOT safe.
 *   - Each bufs[i].len must be > 0.
 *   - The returned cmh_sg_map must remain alive (not freed) until
 *     the hardware completes the scatter-gather operation.  Only then
 *     may cmh_dma_free_sg() be called.
 *   - There is no hardware-imposed limit on @count, but callers are
 *     responsible for bounding it to avoid excessive DMA mappings.
 *     In practice, hash uses <= 2 entries (partial + new data).
 *
 * Return: Opaque cmh_sg_map handle, or NULL on allocation/mapping failure.
 */
struct cmh_sg_map *cmh_dma_build_sg(const struct cmh_dma_buf *bufs, u32 count,
				    gfp_t gfp);

/**
 * cmh_dma_free_sg() - Unmap all buffers and free the SG chain
 * @sgm: Handle from cmh_dma_build_sg(), or NULL (no-op)
 */
void cmh_dma_free_sg(struct cmh_sg_map *sgm);

/*
 * Orphan-DMA context -- generic helper for the noabort submit path.
 *
 * When cmh_tm_submit_sync_noabort() times out with a VCQ still
 * in-flight, the eSW will continue writing to DMA buffers after the
 * caller returns.  Callers wrap their DMA state in this struct and
 * pass cmh_dma_orphan_free as the orphan_cb -- the RH callback frees
 * the mapping + buffer when the VCQ eventually completes.
 *
 * Drain guarantee: cmh_tm_cleanup() calls timer_delete_sync() on each
 * TXN timeout timer and splices all TXQ entries before invoking their
 * completion callbacks.  This ensures no orphan callback can race with
 * or run after TM cleanup completes -- by that point every in-flight
 * transaction has been force-completed and its orphan_cb invoked.
 */
struct cmh_dma_orphan {
	void                    *buf;
	dma_addr_t               addr;
	size_t                   len;
	enum dma_data_direction  dir;
};

void cmh_dma_orphan_free(void *data);

#endif /* CMH_DMA_H */
