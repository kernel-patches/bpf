/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_PAGE_FRAG_CACHE_H
#define _LINUX_PAGE_FRAG_CACHE_H

#include <linux/gfp.h>

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

struct page_frag_cache {
	union {
		void *va;
		/* we maintain a pagecount bias, so that we dont dirty cache
		 * line containing page->_refcount every time we allocate a
		 * fragment. As 'va' is always aligned with the order of the
		 * page allocated, we can reuse the LSB bits for the pagecount
		 * bias, and its bit width happens to be indicated by the
		 * 'size_mask' below.
		 */
		unsigned long pagecnt_bias;

	};
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size_mask:15;
	__u16 pfmemalloc:1;
#else
	__u32 offset:31;
	__u32 pfmemalloc:1;
#endif
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
void *__page_frag_alloc_prepare(struct page_frag_cache *nc, unsigned int fragsz,
				gfp_t gfp_mask);

static inline void *page_frag_alloc_va(struct page_frag_cache *nc,
				       unsigned int fragsz, gfp_t gfp_mask)
{
	void *va;

	va = __page_frag_alloc_prepare(nc, fragsz, gfp_mask);
	if (unlikely(!va))
		return NULL;

	va += nc->offset;
	nc->pagecnt_bias--;
	nc->offset = nc->offset + fragsz;

	return va;
}

static inline void *page_frag_alloc_prepare(struct page_frag_cache *nc,
					    unsigned int *offset,
					    unsigned int *size,
					    gfp_t gfp_mask)
{
	void *va;

	va = __page_frag_alloc_prepare(nc, *size, gfp_mask);
	if (unlikely(!va))
		return NULL;

	*offset = nc->offset;

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	*size = nc->size_mask - *offset + 1;
#else
	*size = PAGE_SIZE - *offset;
#endif

	return va;
}

static inline void *page_frag_alloc_prepare_align(struct page_frag_cache *nc,
						  unsigned int *offset,
						  unsigned int *size,
						  unsigned int align,
						  gfp_t gfp_mask)
{
	unsigned int old_offset = nc->offset;

	WARN_ON_ONCE(!is_power_of_2(align) || align >= PAGE_SIZE ||
		     *size < sizeof(unsigned int));

	nc->offset = ALIGN(old_offset, align);
	return page_frag_alloc_prepare(nc, offset, size, gfp_mask);
}

static inline void page_frag_alloc_commit(struct page_frag_cache *nc,
					  unsigned int offset,
					  unsigned int size)
{
	nc->pagecnt_bias--;
	nc->offset = offset + size;
}

static inline void page_frag_alloc_commit_noref(struct page_frag_cache *nc,
						unsigned int offset,
						unsigned int size)
{
	nc->offset = offset + size;
}

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
	WARN_ON_ONCE(!is_power_of_2(align) || align >= PAGE_SIZE ||
		     fragsz < sizeof(unsigned int));

	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, align);
}

void page_frag_free_va(void *addr);

#endif
