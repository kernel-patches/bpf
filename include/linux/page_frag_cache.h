/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_PAGE_FRAG_CACHE_H
#define _LINUX_PAGE_FRAG_CACHE_H

#include <linux/gfp.h>

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

/*
 * struct encoded_va - a nonexistent type marking this pointer
 *
 * An 'encoded_va' pointer is a pointer to a aligned virtual address, which is
 * at least aligned to PAGE_SIZE, that means there are at least 12 lower bits
 * space available for other purposes.
 *
 * Currently we use the lower 8 bits and bit 9 for the order and PFMEMALLOC
 * flag of the page this 'va' is corresponding to.
 *
 * Use the supplied helper functions to endcode/decode the pointer and bits.
 */
struct encoded_va;

#define PAGE_FRAG_CACHE_ORDER_MASK		GENMASK(7, 0)
#define PAGE_FRAG_CACHE_PFMEMALLOC_BIT		BIT(8)
#define PAGE_FRAG_CACHE_PFMEMALLOC_SHIFT	8

static inline struct encoded_va *encode_aligned_va(void *va,
						   unsigned int order,
						   bool pfmemalloc)
{
	return (struct encoded_va *)((unsigned long)va | order |
			pfmemalloc << PAGE_FRAG_CACHE_PFMEMALLOC_SHIFT);
}

static inline unsigned long encoded_page_order(struct encoded_va *encoded_va)
{
	return PAGE_FRAG_CACHE_ORDER_MASK & (unsigned long)encoded_va;
}

static inline bool encoded_page_pfmemalloc(struct encoded_va *encoded_va)
{
	return PAGE_FRAG_CACHE_PFMEMALLOC_BIT & (unsigned long)encoded_va;
}

static inline void *encoded_page_address(struct encoded_va *encoded_va)
{
	return (void *)((unsigned long)encoded_va & PAGE_MASK);
}

struct page_frag_cache {
	struct encoded_va *encoded_va;

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE) && (BITS_PER_LONG <= 32)
	u16 pagecnt_bias;
	u16 remaining;
#else
	u32 pagecnt_bias;
	u32 remaining;
#endif
};

static inline void page_frag_cache_init(struct page_frag_cache *nc)
{
	memset(nc, 0, sizeof(*nc));
}

static inline bool page_frag_cache_is_pfmemalloc(struct page_frag_cache *nc)
{
	return encoded_page_pfmemalloc(nc->encoded_va);
}

static inline unsigned int page_frag_cache_page_size(struct encoded_va *encoded_va)
{
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	return PAGE_SIZE << encoded_page_order(encoded_va);
#else
	return PAGE_SIZE;
#endif
}

static inline unsigned int __page_frag_cache_page_offset(struct encoded_va *encoded_va,
							 unsigned int remaining)
{
	return page_frag_cache_page_size(encoded_va) - remaining;
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
	WARN_ON_ONCE(!is_power_of_2(align) || align > PAGE_SIZE);
	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, -align);
}

static inline void *page_frag_alloc_va(struct page_frag_cache *nc,
				       unsigned int fragsz, gfp_t gfp_mask)
{
	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, ~0u);
}

void page_frag_free_va(void *addr);

#endif
