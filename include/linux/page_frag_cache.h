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
	WARN_ON_ONCE(!is_power_of_2(align) || align > PAGE_SIZE);
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
	return __page_frag_cache_page_offset(nc->encoded_va, nc->remaining);
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
	WARN_ON_ONCE(!is_power_of_2(align) || align > PAGE_SIZE);
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

static inline struct encoded_va *__page_frag_alloc_probe(struct page_frag_cache *nc,
							 unsigned int *offset,
							 unsigned int *fragsz,
							 void **va)
{
	struct encoded_va *encoded_va;

	*fragsz = nc->remaining;
	encoded_va = nc->encoded_va;
	*offset = __page_frag_cache_page_offset(encoded_va, *fragsz);
	*va = encoded_page_address(encoded_va) + *offset;

	return encoded_va;
}

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
#define page_frag_alloc_probe(nc, offset, fragsz, va)			\
({									\
	struct page *__page = NULL;					\
									\
	VM_BUG_ON(!*(fragsz));						\
	if (likely((nc)->remaining >= *(fragsz)))			\
		__page = virt_to_page(__page_frag_alloc_probe(nc,	\
							      offset,	\
							      fragsz,	\
							      va));	\
									\
	__page;								\
})

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
 * page_frag_alloc_abort - Abort the page fragment alloced using page_frag_alloc()
 * related API back to the page_frag cache.
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
