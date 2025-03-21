// SPDX-License-Identifier: GPL-2.0

#include <linux/bits.h>
#include <linux/device.h>
#include <linux/device/bus.h>
#include <linux/dma-direct.h>
#include <linux/dma-direction.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/gfp_types.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/notifier.h>
#include <linux/pfn.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

static void *eyeq5_iocu_alloc(struct device *dev, size_t size,
			      dma_addr_t *dma_handle, gfp_t gfp,
			      unsigned long attrs)
{
	void *p = dma_direct_alloc(dev, size, dma_handle, gfp, attrs);

	*dma_handle |= BIT_ULL(36);
	return p;
}

static void eyeq5_iocu_free(struct device *dev, size_t size,
			    void *vaddr, dma_addr_t dma_handle,
			    unsigned long attrs)
{
	dma_handle &= ~BIT_ULL(36);
	dma_direct_free(dev, size, vaddr, dma_handle, attrs);
}

static int eyeq5_iocu_mmap(struct device *dev, struct vm_area_struct *vma,
			   void *cpu_addr, dma_addr_t dma_addr, size_t size,
			   unsigned long attrs)
{
	unsigned long pfn = PHYS_PFN(dma_to_phys(dev, dma_addr));
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long user_count = vma_pages(vma);
	int ret;

	vma->vm_page_prot = dma_pgprot(dev, vma->vm_page_prot, attrs);

	if (dma_mmap_from_dev_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;

	if (vma->vm_pgoff >= count || user_count > count - vma->vm_pgoff)
		return -ENXIO;

	return remap_pfn_range(vma, vma->vm_start, pfn + vma->vm_pgoff,
			       user_count << PAGE_SHIFT, vma->vm_page_prot);
}

static int eyeq5_iocu_get_sgtable(struct device *dev, struct sg_table *sgt,
				  void *cpu_addr, dma_addr_t dma_addr, size_t size,
				  unsigned long attrs)
{
	struct page *page = virt_to_page(cpu_addr);
	int ret;

	ret = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (!ret)
		sg_set_page(sgt->sgl, page, PAGE_ALIGN(size), 0);
	return ret;
}

static dma_addr_t eyeq5_iocu_map_page(struct device *dev, struct page *page,
				      unsigned long offset, size_t size,
				      enum dma_data_direction dir,
				      unsigned long attrs)
{
	phys_addr_t phys = page_to_phys(page) + offset;

	/* BIT(36) toggles routing through IOCU for DMA operations. */
	return phys_to_dma(dev, phys) | BIT_ULL(36);
}

static void eyeq5_iocu_unmap_page(struct device *dev, dma_addr_t dma_handle,
				  size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
}

static int eyeq5_iocu_map_sg(struct device *dev, struct scatterlist *sgl,
			     int nents, enum dma_data_direction dir,
			     unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		sg->dma_address = eyeq5_iocu_map_page(dev, sg_page(sg),
						      sg->offset, sg->length,
						      dir, attrs);
		if (sg->dma_address == DMA_MAPPING_ERROR)
			return 0; /* No cleanup because ->unmap_page() is a no-op. */
		sg_dma_len(sg) = sg->length;
	}

	return nents;
}

static void eyeq5_iocu_unmap_sg(struct device *dev, struct scatterlist *sgl,
				int nents, enum dma_data_direction dir,
				unsigned long attrs)
{
	/* We know page ->unmap_page() is a no-op. */
}

const struct dma_map_ops eyeq5_iocu_ops = {
	.alloc			= eyeq5_iocu_alloc,
	.free			= eyeq5_iocu_free,
	.alloc_pages_op		= dma_direct_alloc_pages,
	.free_pages		= dma_direct_free_pages,
	.mmap			= eyeq5_iocu_mmap,
	.get_sgtable		= eyeq5_iocu_get_sgtable,
	.map_page		= eyeq5_iocu_map_page,
	.unmap_page		= eyeq5_iocu_unmap_page,
	.map_sg			= eyeq5_iocu_map_sg,
	.unmap_sg		= eyeq5_iocu_unmap_sg,
	.get_required_mask	= dma_direct_get_required_mask,
};
EXPORT_SYMBOL(eyeq5_iocu_ops);

static int eyeq5_iocu_notifier(struct notifier_block *nb,
			       unsigned long event,
			       void *data)
{
	struct device *dev = data;

	/*
	 * IOCU routing is hardwired; we must use our above custom
	 * routines for cache-coherent DMA on ethernet interfaces.
	 */
	if (event == BUS_NOTIFY_ADD_DEVICE &&
	    device_is_compatible(dev, "mobileye,eyeq5-gem")) {
		set_dma_ops(dev, &eyeq5_iocu_ops);
		return NOTIFY_OK;
	}

	return NOTIFY_DONE;
}

static struct notifier_block eyeq5_iocu_nb = {
	.notifier_call = eyeq5_iocu_notifier,
};

static int __init eyeq5_iocu_init(void)
{
	return bus_register_notifier(&platform_bus_type, &eyeq5_iocu_nb);
}
postcore_initcall(eyeq5_iocu_init);
