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
#include <linux/gfp_types.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/page_frag_cache.h>
#include "internal.h"

static struct page *__page_frag_cache_recharge(struct page_frag_cache *nc)
{
	unsigned long encoded_va = nc->encoded_va;
	struct page *page;

	page = virt_to_page((void *)encoded_va);
	if (!page_ref_sub_and_test(page, nc->pagecnt_bias))
		return NULL;

	if (unlikely(encoded_page_pfmemalloc(encoded_va))) {
		VM_BUG_ON(compound_order(page) !=
			  encoded_page_order(encoded_va));
		free_unref_page(page, encoded_page_order(encoded_va));
		return NULL;
	}

	/* OK, page count is 0, we can safely set it */
	set_page_count(page, PAGE_FRAG_CACHE_MAX_SIZE + 1);

	return page;
}

static struct page *__page_frag_cache_refill(struct page_frag_cache *nc,
					     gfp_t gfp_mask)
{
	unsigned long order = PAGE_FRAG_CACHE_MAX_ORDER;
	struct page *page = NULL;
	gfp_t gfp = gfp_mask;

	if (likely(nc->encoded_va)) {
		page = __page_frag_cache_recharge(nc);
		if (page) {
			order = encoded_page_order(nc->encoded_va);
			goto out;
		}
	}

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	gfp_mask = (gfp_mask & ~__GFP_DIRECT_RECLAIM) |  __GFP_COMP |
		   __GFP_NOWARN | __GFP_NORETRY | __GFP_NOMEMALLOC;
	page = alloc_pages_node(NUMA_NO_NODE, gfp_mask,
				PAGE_FRAG_CACHE_MAX_ORDER);
#endif
	if (unlikely(!page)) {
		page = alloc_pages_node(NUMA_NO_NODE, gfp, 0);
		if (unlikely(!page)) {
			memset(nc, 0, sizeof(*nc));
			return NULL;
		}

		order = 0;
	}

	nc->encoded_va = encode_aligned_va(page_address(page), order,
					   page_is_pfmemalloc(page));

	/* Even if we own the page, we do not use atomic_set().
	 * This would break get_page_unless_zero() users.
	 */
	page_ref_add(page, PAGE_FRAG_CACHE_MAX_SIZE);

out:
	/* reset page count bias and remaining to start of new frag */
	nc->pagecnt_bias = PAGE_FRAG_CACHE_MAX_SIZE + 1;
	nc->remaining = PAGE_SIZE << order;

	return page;
}

void page_frag_cache_drain(struct page_frag_cache *nc)
{
	if (!nc->encoded_va)
		return;

	__page_frag_cache_drain(virt_to_head_page((void *)nc->encoded_va),
				nc->pagecnt_bias);
	memset(nc, 0, sizeof(*nc));
}
EXPORT_SYMBOL(page_frag_cache_drain);

void __page_frag_cache_drain(struct page *page, unsigned int count)
{
	VM_BUG_ON_PAGE(page_ref_count(page) == 0, page);

	if (page_ref_sub_and_test(page, count))
		free_unref_page(page, compound_order(page));
}
EXPORT_SYMBOL(__page_frag_cache_drain);

void *__page_frag_alloc_va_align(struct page_frag_cache *nc,
				 unsigned int fragsz, gfp_t gfp_mask,
				 unsigned int align_mask)
{
	unsigned int size = page_frag_cache_page_size(nc->encoded_va);
	unsigned int remaining = nc->remaining & align_mask;

	if (unlikely(remaining < fragsz)) {
		if (unlikely(fragsz > PAGE_SIZE)) {
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

		if (unlikely(!__page_frag_cache_refill(nc, gfp_mask)))
			return NULL;

		size = page_frag_cache_page_size(nc->encoded_va);
		remaining = size;
	}

	nc->pagecnt_bias--;
	nc->remaining = remaining - fragsz;

	return encoded_page_address(nc->encoded_va) + (size - remaining);
}
EXPORT_SYMBOL(__page_frag_alloc_va_align);

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
