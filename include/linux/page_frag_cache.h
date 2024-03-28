/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_PAGE_FRAG_CACHE_H
#define _LINUX_PAGE_FRAG_CACHE_H

#include <linux/gfp.h>

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

struct page_frag_cache {
	void *va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size_mask:15;
	__u16 pfmemalloc:1;
#else
	__u32 offset:31;
	__u32 pfmemalloc:1;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_refcount every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
};

static inline void page_frag_cache_init(struct page_frag_cache *nc)
{
	nc->va = NULL;
}

static inline bool page_frag_cache_is_pfmemalloc(struct page_frag_cache *nc)
{
	return !!nc->pfmemalloc;
}

void page_frag_cache_drain(struct page_frag_cache *nc);
void __page_frag_cache_drain(struct page *page, unsigned int count);
void *page_frag_alloc_va(struct page_frag_cache *nc, unsigned int fragsz,
			 gfp_t gfp_mask);

static inline void *__page_frag_alloc_va_align(struct page_frag_cache *nc,
					       unsigned int fragsz,
					       gfp_t gfp_mask,
					       unsigned int align)
{
	unsigned int offset = nc->offset;

	nc->offset = ALIGN(offset, align);

	return page_frag_alloc_va(nc, fragsz, gfp_mask);
}

static inline void *page_frag_alloc_va_align(struct page_frag_cache *nc,
					     unsigned int fragsz,
					     gfp_t gfp_mask,
					     unsigned int align)
{
	WARN_ON_ONCE(!is_power_of_2(align) || align >= PAGE_SIZE);

	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, align);
}

void page_frag_free_va(void *addr);

#endif
