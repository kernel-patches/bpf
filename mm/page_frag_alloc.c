// SPDX-License-Identifier: GPL-2.0-only
/* Page fragment allocator
 *
 * Page Fragment:
 *  An arbitrary-length arbitrary-offset area of memory which resides within a
 *  0 or higher order page.  Multiple fragments within that page are
 *  individually refcounted, in the page's reference counter.
 *
 * The page_frag functions provide a simple allocation framework for page
 * fragments.  This is used by the network stack and network device drivers to
 * provide a backing region of memory for use as either an sk_buff->head, or to
 * be used in the "frags" portion of skb_shared_info.
 */

#include <linux/export.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/page_frag_cache.h>
#include "internal.h"

static bool __page_frag_cache_refill(struct page_frag_cache *nc,
				     gfp_t gfp_mask)
{
	struct page *page = NULL;
	gfp_t gfp = gfp_mask;

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	gfp_mask = (gfp_mask & ~__GFP_DIRECT_RECLAIM) |  __GFP_COMP |
		   __GFP_NOWARN | __GFP_NORETRY | __GFP_NOMEMALLOC;
	page = alloc_pages_node(NUMA_NO_NODE, gfp_mask,
				PAGE_FRAG_CACHE_MAX_ORDER);
	nc->size_mask = page ? PAGE_FRAG_CACHE_MAX_SIZE - 1 : PAGE_SIZE - 1;
	VM_BUG_ON(page && nc->size_mask != PAGE_FRAG_CACHE_MAX_SIZE - 1);
#endif
	if (unlikely(!page))
		page = alloc_pages_node(NUMA_NO_NODE, gfp, 0);

	if (unlikely(!page)) {
		nc->va = NULL;
		return false;
	}

	nc->va = page_address(page);

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	VM_BUG_ON(nc->pagecnt_bias & nc->size_mask);
	page_ref_add(page, nc->size_mask - 1);
	nc->pagecnt_bias |= nc->size_mask;
#else
	VM_BUG_ON(nc->pagecnt_bias & (PAGE_SIZE - 1));
	page_ref_add(page, PAGE_SIZE - 2);
	nc->pagecnt_bias |= (PAGE_SIZE - 1);
#endif

	nc->pfmemalloc = page_is_pfmemalloc(page);
	nc->offset = 0;
	return true;
}

void page_frag_cache_drain(struct page_frag_cache *nc)
{
	if (!nc->va)
		return;

	__page_frag_cache_drain(virt_to_head_page(nc->va), nc->pagecnt_bias);
	nc->va = NULL;
}
EXPORT_SYMBOL(page_frag_cache_drain);

void __page_frag_cache_drain(struct page *page, unsigned int count)
{
	VM_BUG_ON_PAGE(page_ref_count(page) == 0, page);

	/* ensure we can call free_unref_page() directly as we are bypassing
	 * the pcp_allowed_order() checking.
	 */
	VM_BUG_ON(PAGE_FRAG_CACHE_MAX_ORDER > PAGE_ALLOC_COSTLY_ORDER);

	if (page_ref_sub_and_test(page, count))
		free_unref_page(page, compound_order(page));
}
EXPORT_SYMBOL(__page_frag_cache_drain);

void *page_frag_alloc_va(struct page_frag_cache *nc, unsigned int fragsz,
			 gfp_t gfp_mask)
{
	unsigned long size_mask;
	unsigned int offset;
	struct page *page;
	void *va;

	if (unlikely(!nc->va)) {
refill:
		if (!__page_frag_cache_refill(nc, gfp_mask))
			return NULL;
	}

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	/* if size can vary use size else just use PAGE_SIZE */
	size_mask = nc->size_mask;
#else
	size_mask = PAGE_SIZE - 1;
#endif

	va = (void *)((unsigned long)nc->va & ~size_mask);
	offset = nc->offset;

	if (unlikely(offset + fragsz > (size_mask + 1))) {
		page = virt_to_page(va);

		if (!page_ref_sub_and_test(page, nc->pagecnt_bias & size_mask))
			goto refill;

		if (unlikely(nc->pfmemalloc)) {
			free_unref_page(page, compound_order(page));
			goto refill;
		}

		/* OK, page count is 0, we can safely set it */
		set_page_count(page, size_mask);
		nc->pagecnt_bias |= size_mask;

		offset = 0;
		if (unlikely(fragsz > (size_mask + 1))) {
			/*
			 * The caller is trying to allocate a fragment
			 * with fragsz > PAGE_SIZE but the cache isn't big
			 * enough to satisfy the request, this may
			 * happen in low memory conditions.
			 * We don't release the cache page because
			 * it could make memory pressure worse
			 * so we simply return NULL here.
			 */
			return NULL;
		}
	}

	nc->pagecnt_bias--;
	nc->offset = offset + fragsz;

	return va + offset;
}
EXPORT_SYMBOL(page_frag_alloc_va);

/*
 * Frees a page fragment allocated out of either a compound or order 0 page.
 */
void page_frag_free_va(void *addr)
{
	struct page *page = virt_to_head_page(addr);

	if (unlikely(put_page_testzero(page)))
		free_unref_page(page, compound_order(page));
}
EXPORT_SYMBOL(page_frag_free_va);
