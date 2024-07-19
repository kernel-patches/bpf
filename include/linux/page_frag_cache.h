/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_PAGE_FRAG_CACHE_H
#define _LINUX_PAGE_FRAG_CACHE_H

#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/mm_types_task.h>
#include <asm/page.h>

#define PAGE_FRAG_CACHE_ORDER_MASK		GENMASK(7, 0)
#define PAGE_FRAG_CACHE_PFMEMALLOC_BIT		BIT(8)
#define PAGE_FRAG_CACHE_PFMEMALLOC_SHIFT	8

static inline unsigned long encode_aligned_va(void *va, unsigned int order,
					      bool pfmemalloc)
{
	BUILD_BUG_ON(PAGE_FRAG_CACHE_MAX_ORDER > PAGE_FRAG_CACHE_ORDER_MASK);
	BUILD_BUG_ON(PAGE_FRAG_CACHE_PFMEMALLOC_SHIFT >= PAGE_SHIFT);

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	return (unsigned long)va | order |
		(pfmemalloc << PAGE_FRAG_CACHE_PFMEMALLOC_SHIFT);
#else
	return (unsigned long)va |
		(pfmemalloc << PAGE_FRAG_CACHE_PFMEMALLOC_SHIFT);
#endif
}

static inline unsigned long encoded_page_order(unsigned long encoded_va)
{
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	return encoded_va & PAGE_FRAG_CACHE_ORDER_MASK;
#else
	return 0;
#endif
}

static inline bool encoded_page_pfmemalloc(unsigned long encoded_va)
{
	return encoded_va & PAGE_FRAG_CACHE_PFMEMALLOC_BIT;
}

static inline void *encoded_page_address(unsigned long encoded_va)
{
	return (void *)(encoded_va & PAGE_MASK);
}

static inline void page_frag_cache_init(struct page_frag_cache *nc)
{
	memset(nc, 0, sizeof(*nc));
}

static inline bool page_frag_cache_is_pfmemalloc(struct page_frag_cache *nc)
{
	return encoded_page_pfmemalloc(nc->encoded_va);
}

static inline unsigned int page_frag_cache_page_size(unsigned long encoded_va)
{
	return PAGE_SIZE << encoded_page_order(encoded_va);
}

void page_frag_cache_drain(struct page_frag_cache *nc);
void __page_frag_cache_drain(struct page *page, unsigned int count);
void *__page_frag_alloc_va_align(struct page_frag_cache *nc,
				 unsigned int fragsz, gfp_t gfp_mask,
				 unsigned int align_mask);

static inline void *page_frag_alloc_va_align(struct page_frag_cache *nc,
					     unsigned int fragsz,
					     gfp_t gfp_mask, unsigned int align)
{
	WARN_ON_ONCE(!is_power_of_2(align));
	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, -align);
}

static inline void *page_frag_alloc_va(struct page_frag_cache *nc,
				       unsigned int fragsz, gfp_t gfp_mask)
{
	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, ~0u);
}

void page_frag_free_va(void *addr);

#endif
