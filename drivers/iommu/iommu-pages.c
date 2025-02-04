// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include "iommu-pages.h"
#include <linux/gfp.h>
#include <linux/mm.h>

#define IOPTDESC_MATCH(pg_elm, elm)                    \
	static_assert(offsetof(struct page, pg_elm) == \
		      offsetof(struct ioptdesc, elm))
IOPTDESC_MATCH(flags, __page_flags);
IOPTDESC_MATCH(lru, iopt_freelist_elm); /* Ensure bit 0 is clear */
IOPTDESC_MATCH(mapping, __page_mapping);
IOPTDESC_MATCH(private, _private);
IOPTDESC_MATCH(page_type, __page_type);
IOPTDESC_MATCH(_refcount, __page_refcount);
#ifdef CONFIG_MEMCG
IOPTDESC_MATCH(memcg_data, memcg_data);
#endif
#undef IOPTDESC_MATCH
static_assert(sizeof(struct ioptdesc) <= sizeof(struct page));

/**
 * iommu_alloc_pages_node - Allocate a zeroed page of a given order from
 *                          specific NUMA node
 * @nid: memory NUMA node id
 * @gfp: buddy allocator flags
 * @order: page order
 *
 * Returns the virtual address of the allocated page. The page must be
 * freed either by calling iommu_free_page() or via iommu_put_pages_list().
 */
void *iommu_alloc_pages_node(int nid, gfp_t gfp, unsigned int order)
{
	const unsigned long pgcnt = 1UL << order;
	struct folio *folio;

	/*
	 * __folio_alloc_node() does not handle NUMA_NO_NODE like
	 * alloc_pages_node() did.
	 */
	if (nid == NUMA_NO_NODE)
		nid = numa_mem_id();

	folio = __folio_alloc_node(gfp | __GFP_ZERO, order, nid);
	if (unlikely(!folio))
		return NULL;

	/*
	 * All page allocations that should be reported to as "iommu-pagetables"
	 * to userspace must use one of the functions below. This includes
	 * allocations of page-tables and other per-iommu_domain configuration
	 * structures.
	 *
	 * This is necessary for the proper accounting as IOMMU state can be
	 * rather large, i.e. multiple gigabytes in size.
	 */
	mod_node_page_state(folio_pgdat(folio), NR_IOMMU_PAGES, pgcnt);
	lruvec_stat_mod_folio(folio, NR_SECONDARY_PAGETABLE, pgcnt);

	return folio_address(folio);
}
EXPORT_SYMBOL_GPL(iommu_alloc_pages_node);

static void __iommu_free_page(struct ioptdesc *iopt)
{
	struct folio *folio = ioptdesc_folio(iopt);
	const unsigned long pgcnt = 1UL << folio_order(folio);

	mod_node_page_state(folio_pgdat(folio), NR_IOMMU_PAGES, -pgcnt);
	lruvec_stat_mod_folio(folio, NR_SECONDARY_PAGETABLE, -pgcnt);
	folio_put(folio);
}

/**
 * iommu_free_page - free page of any  order
 * @virt: virtual address of the page to be freed.
 *
 * Frees the allocation from iommu_alloc_pages_node()
 */
void iommu_free_page(void *virt)
{
	if (!virt)
		return;
	__iommu_free_page(virt_to_ioptdesc(virt));
}
EXPORT_SYMBOL_GPL(iommu_free_page);

/**
 * iommu_put_pages_list - free a list of pages.
 * @list: The list of pages to be freed
 *
 * Frees a list of pages allocated by iommu_alloc_pages_node().
 */
void iommu_put_pages_list(struct iommu_pages_list *list)
{
	struct ioptdesc *iopt, *tmp;

	list_for_each_entry_safe(iopt, tmp, &list->pages, iopt_freelist_elm)
		__iommu_free_page(iopt);
}
EXPORT_SYMBOL_GPL(iommu_put_pages_list);
