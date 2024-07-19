/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_PAGE_FRAG_CACHE_H
#define _LINUX_PAGE_FRAG_CACHE_H

#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mmdebug.h>
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

/**
 * page_frag_cache_init() - Init page_frag cache.
 * @nc: page_frag cache from which to init
 *
 * Inline helper to init the page_frag cache.
 */
static inline void page_frag_cache_init(struct page_frag_cache *nc)
{
	memset(nc, 0, sizeof(*nc));
}

/**
 * page_frag_cache_is_pfmemalloc() - Check for pfmemalloc.
 * @nc: page_frag cache from which to check
 *
 * Used to check if the current page in page_frag cache is pfmemalloc'ed.
 * It has the same calling context expection as the alloc API.
 *
 * Return:
 * true if the current page in page_frag cache is pfmemalloc'ed, otherwise
 * return false.
 */
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
struct page *page_frag_alloc_pg(struct page_frag_cache *nc,
				unsigned int *offset, unsigned int fragsz,
				gfp_t gfp);
void *__page_frag_alloc_va_align(struct page_frag_cache *nc,
				 unsigned int fragsz, gfp_t gfp_mask,
				 unsigned int align_mask);

/**
 * page_frag_alloc_va_align() - Alloc a page fragment with aligning requirement.
 * @nc: page_frag cache from which to allocate
 * @fragsz: the requested fragment size
 * @gfp_mask: the allocation gfp to use when cache needs to be refilled
 * @align: the requested aligning requirement for virtual address of fragment
 *
 * WARN_ON_ONCE() checking for @align before allocing a page fragment from
 * page_frag cache with aligning requirement.
 *
 * Return:
 * virtual address of the page fragment, otherwise return NULL.
 */
static inline void *page_frag_alloc_va_align(struct page_frag_cache *nc,
					     unsigned int fragsz,
					     gfp_t gfp_mask, unsigned int align)
{
	WARN_ON_ONCE(!is_power_of_2(align));
	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, -align);
}

/**
 * page_frag_cache_page_offset() - Return the current page fragment's offset.
 * @nc: page_frag cache from which to check
 *
 * The API is only used in net/sched/em_meta.c for historical reason, do not use
 * it for new caller unless there is a strong reason.
 *
 * Return:
 * the offset of the current page fragment in the page_frag cache.
 */
static inline unsigned int page_frag_cache_page_offset(const struct page_frag_cache *nc)
{
	return page_frag_cache_page_size(nc->encoded_va) - nc->remaining;
}

/**
 * page_frag_alloc_va() - Alloc a page fragment.
 * @nc: page_frag cache from which to allocate
 * @fragsz: the requested fragment size
 * @gfp_mask: the allocation gfp to use when cache need to be refilled
 *
 * Get a page fragment from page_frag cache.
 *
 * Return:
 * virtual address of the page fragment, otherwise return NULL.
 */
static inline void *page_frag_alloc_va(struct page_frag_cache *nc,
				       unsigned int fragsz, gfp_t gfp_mask)
{
	return __page_frag_alloc_va_align(nc, fragsz, gfp_mask, ~0u);
}

void *page_frag_alloc_va_prepare(struct page_frag_cache *nc, unsigned int *fragsz,
				 gfp_t gfp);

/**
 * page_frag_alloc_va_prepare_align() - Prepare allocing a page fragment with
 * aligning requirement.
 * @nc: page_frag cache from which to prepare
 * @fragsz: in as the requested size, out as the available size
 * @gfp: the allocation gfp to use when cache need to be refilled
 * @align: the requested aligning requirement
 *
 * WARN_ON_ONCE() checking for @align before preparing an aligned page fragment
 * with minimum size of @fragsz, @fragsz is also used to report the maximum size
 * of the page fragment the caller can use.
 *
 * Return:
 * virtual address of the page fragment, otherwise return NULL.
 */
static inline void *page_frag_alloc_va_prepare_align(struct page_frag_cache *nc,
						     unsigned int *fragsz,
						     gfp_t gfp,
						     unsigned int align)
{
	WARN_ON_ONCE(!is_power_of_2(align));
	nc->remaining = nc->remaining & -align;
	return page_frag_alloc_va_prepare(nc, fragsz, gfp);
}

struct page *page_frag_alloc_pg_prepare(struct page_frag_cache *nc,
					unsigned int *offset,
					unsigned int *fragsz, gfp_t gfp);

struct page *page_frag_alloc_prepare(struct page_frag_cache *nc,
				     unsigned int *offset,
				     unsigned int *fragsz,
				     void **va, gfp_t gfp);

/**
 * page_frag_alloc_probe - Probe the available page fragment.
 * @nc: page_frag cache from which to probe
 * @offset: out as the offset of the page fragment
 * @fragsz: in as the requested size, out as the available size
 * @va: out as the virtual address of the returned page fragment
 *
 * Probe the current available memory to caller without doing cache refilling.
 * If no space is available in the page_frag cache, return NULL.
 * If the requested space is available, up to @fragsz bytes may be added to the
 * fragment using commit API.
 *
 * Return:
 * the page fragment, otherwise return NULL.
 */
static inline struct page *page_frag_alloc_probe(struct page_frag_cache *nc,
						 unsigned int *offset,
						 unsigned int *fragsz,
						 void **va)
{
	unsigned long encoded_va;
	struct page *page;

	VM_BUG_ON(!*fragsz);
	if (unlikely(nc->remaining < *fragsz))
		return NULL;

	*fragsz = nc->remaining;
	encoded_va = nc->encoded_va;
	*va = encoded_page_address(encoded_va);
	page = virt_to_page(*va);
	*offset = page_frag_cache_page_size(encoded_va) - *fragsz;
	*va += *offset;

	return page;
}

/**
 * page_frag_alloc_commit - Commit allocing a page fragment.
 * @nc: page_frag cache from which to commit
 * @fragsz: size of the page fragment has been used
 *
 * Commit the actual used size for the allocation that was either prepared or
 * probed.
 */
static inline void page_frag_alloc_commit(struct page_frag_cache *nc,
					  unsigned int fragsz)
{
	VM_BUG_ON(fragsz > nc->remaining || !nc->pagecnt_bias);
	nc->pagecnt_bias--;
	nc->remaining -= fragsz;
}

/**
 * page_frag_alloc_commit_noref - Commit allocing a page fragment without taking
 * page refcount.
 * @nc: page_frag cache from which to commit
 * @fragsz: size of the page fragment has been used
 *
 * Commit the alloc preparing or probing by passing the actual used size, but
 * not taking refcount. Mostly used for fragmemt coalescing case when the
 * current fragment can share the same refcount with previous fragment.
 */
static inline void page_frag_alloc_commit_noref(struct page_frag_cache *nc,
						unsigned int fragsz)
{
	VM_BUG_ON(fragsz > nc->remaining);
	nc->remaining -= fragsz;
}

/**
 * page_frag_alloc_abort - Abort the page fragment allocation.
 * @nc: page_frag cache to which the page fragment is aborted back
 * @fragsz: size of the page fragment to be aborted
 *
 * It is expected to be called from the same context as the alloc API.
 * Mostly used for error handling cases where the fragment is no longer needed.
 */
static inline void page_frag_alloc_abort(struct page_frag_cache *nc,
					 unsigned int fragsz)
{
	nc->pagecnt_bias++;
	nc->remaining += fragsz;
}

void page_frag_free_va(void *addr);

#endif
