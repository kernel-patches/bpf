// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN shadow implementation.
 *
 * Copyright (C) 2017-2022 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#include <asm/kmsan.h>
#include <asm/tlbflush.h>
#include <linux/bits.h>
#include <linux/cacheflush.h>
#include <linux/memblock.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/stddef.h>

#include "../internal.h"
#include "../vmalloc.h"
#include "kmsan.h"

#define KMSAN_META_MASK_SHADOW		BIT(0)
#define KMSAN_META_MASK_ORIGIN		BIT(1)

struct page_metadata {
	struct page *shadow;
	struct page *origin;
};

static inline struct page_metadata get_page_metadata(struct page *page)
{
	return (struct page_metadata) {
		.shadow = page->kmsan_shadow,
		.origin = page->kmsan_origin,
	};
}

static inline void set_page_metadata(struct page *page, struct page_metadata meta)
{
	page->kmsan_shadow = meta.shadow;
	page->kmsan_origin = meta.origin;
}

static inline void *shadow_ptr_for(struct page_metadata meta)
{
	return page_address(meta.shadow);
}

static inline void *origin_ptr_for(struct page_metadata meta)
{
	return page_address(meta.origin);
}

static inline bool page_has_metadata(struct page_metadata meta)
{
	return meta.shadow && meta.origin;
}

static void set_no_shadow_origin_page(struct page *page)
{
	set_page_metadata(page, (struct page_metadata) {});
}

/*
 * Dummy load and store pages to be used when the real metadata is unavailable.
 * There are separate pages for loads and stores, so that every load returns a
 * zero, and every store doesn't affect other loads.
 */
static char dummy_load_page[PAGE_SIZE] __aligned(PAGE_SIZE);
static char dummy_store_page[PAGE_SIZE] __aligned(PAGE_SIZE);

static unsigned long vmalloc_meta(void *addr, bool is_origin)
{
	unsigned long addr64 = (unsigned long)addr, off;

	KMSAN_WARN_ON(is_origin && !IS_ALIGNED(addr64, KMSAN_ORIGIN_SIZE));
	if (kmsan_internal_is_vmalloc_addr(addr)) {
		off = addr64 - VMALLOC_START;
		return off + (is_origin ? KMSAN_VMALLOC_ORIGIN_START :
					  KMSAN_VMALLOC_SHADOW_START);
	}
	if (kmsan_internal_is_module_addr(addr)) {
		off = addr64 - MODULES_VADDR;
		return off + (is_origin ? KMSAN_MODULES_ORIGIN_START :
					  KMSAN_MODULES_SHADOW_START);
	}
	return 0;
}

static struct page *virt_to_page_or_null(void *vaddr)
{
	if (kmsan_virt_addr_valid(vaddr))
		return virt_to_page(vaddr);
	else
		return NULL;
}

static __always_inline
struct shadow_origin_ptr __kmsan_get_metadata(void *address, unsigned int mask)
{
	struct shadow_origin_ptr ret = {};
	struct page_metadata meta;
	struct page *page;
	u64 addr = (u64)address;
	u64 origin_addr = ALIGN_DOWN(addr, KMSAN_ORIGIN_SIZE);

	if (kmsan_internal_is_vmalloc_addr(address) ||
	    kmsan_internal_is_module_addr(address)) {
		if (mask & KMSAN_META_MASK_SHADOW)
			ret.shadow = (void *)vmalloc_meta(address, KMSAN_META_SHADOW);
		if (mask & KMSAN_META_MASK_ORIGIN)
			ret.origin = (void *)vmalloc_meta((void *)origin_addr,
							  KMSAN_META_ORIGIN);
		return ret;
	}

	if (mask & KMSAN_META_MASK_SHADOW) {
		ret.shadow = arch_kmsan_get_meta_or_null(address, KMSAN_META_SHADOW);
		if (!ret.shadow)
			goto lookup_page;
	}
	if (mask & KMSAN_META_MASK_ORIGIN)
		ret.origin = arch_kmsan_get_meta_or_null((void *)origin_addr,
							 KMSAN_META_ORIGIN);
	if (ret.shadow || ret.origin)
		return ret;

lookup_page:
	page = virt_to_page_or_null(address);
	if (!page)
		return ret;
	meta = get_page_metadata(page);
	if (!page_has_metadata(meta))
		return ret;

	if (mask & KMSAN_META_MASK_SHADOW)
		ret.shadow = shadow_ptr_for(meta) + offset_in_page(addr);
	if (mask & KMSAN_META_MASK_ORIGIN)
		ret.origin = origin_ptr_for(meta) + offset_in_page(origin_addr);

	return ret;
}

struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *address, u64 size,
						     bool store)
{
	struct shadow_origin_ptr ret;

	/*
	 * Even if we redirect this memory access to the dummy page, it will
	 * go out of bounds.
	 */
	KMSAN_WARN_ON(size > PAGE_SIZE);

	if (!kmsan_enabled)
		goto return_dummy;

	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(address, size));
	ret = __kmsan_get_metadata(address, KMSAN_META_MASK_SHADOW |
					    KMSAN_META_MASK_ORIGIN);
	if (!ret.shadow)
		goto return_dummy;
	return ret;

return_dummy:
	if (store) {
		/* Ignore this store. */
		ret.shadow = dummy_store_page;
		ret.origin = dummy_store_page;
	} else {
		/* This load will return zero. */
		ret.shadow = dummy_load_page;
		ret.origin = dummy_load_page;
	}
	return ret;
}

/*
 * Obtain the shadow or origin pointer for the given address, or NULL if there's
 * none. The caller must check the return value for being non-NULL if needed.
 * The return value of this function should not depend on whether we're in the
 * runtime or not.
 */
void *kmsan_get_metadata(void *address, bool is_origin)
{
	struct shadow_origin_ptr ret;
	unsigned int mask;

	mask = is_origin ? KMSAN_META_MASK_ORIGIN : KMSAN_META_MASK_SHADOW;
	ret = __kmsan_get_metadata(address, mask);
	return is_origin ? ret.origin : ret.shadow;
}

void kmsan_copy_page_meta(struct page *dst, struct page *src)
{
	struct page_metadata dst_meta, src_meta;

	if (!kmsan_enabled || kmsan_in_runtime())
		return;
	if (!dst)
		return;
	dst_meta = get_page_metadata(dst);
	if (!page_has_metadata(dst_meta))
		return;
	if (src)
		src_meta = get_page_metadata(src);
	if (!src || !page_has_metadata(src_meta)) {
		kmsan_internal_unpoison_memory(page_address(dst), PAGE_SIZE,
					       /*checked*/ false);
		return;
	}

	kmsan_enter_runtime();
	__memcpy(shadow_ptr_for(dst_meta), shadow_ptr_for(src_meta), PAGE_SIZE);
	__memcpy(origin_ptr_for(dst_meta), origin_ptr_for(src_meta), PAGE_SIZE);
	kmsan_leave_runtime();
}
EXPORT_SYMBOL(kmsan_copy_page_meta);

void kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags)
{
	bool initialized = (flags & __GFP_ZERO) || !kmsan_enabled;
	struct page_metadata meta;
	depot_stack_handle_t handle;
	int pages = 1 << order;

	if (!page)
		return;

	meta = get_page_metadata(page);

	if (initialized) {
		__memset(shadow_ptr_for(meta), 0, PAGE_SIZE * pages);
		__memset(origin_ptr_for(meta), 0, PAGE_SIZE * pages);
		return;
	}

	/* Zero pages allocated by the runtime should also be initialized. */
	if (kmsan_in_runtime())
		return;

	__memset(shadow_ptr_for(meta), -1, PAGE_SIZE * pages);
	kmsan_enter_runtime();
	handle = kmsan_save_stack_with_flags(flags, /*extra_bits*/ 0);
	kmsan_leave_runtime();
	/*
	 * Addresses are page-aligned, pages are contiguous, so it's ok
	 * to just fill the origin pages with @handle.
	 */
	for (int i = 0; i < PAGE_SIZE * pages / sizeof(handle); i++)
		((depot_stack_handle_t *)origin_ptr_for(meta))[i] = handle;
}

void kmsan_free_page(struct page *page, unsigned int order)
{
	if (!kmsan_enabled || kmsan_in_runtime())
		return;
	kmsan_enter_runtime();
	kmsan_internal_poison_memory(page_address(page), PAGE_SIZE << order,
				     GFP_KERNEL & ~(__GFP_RECLAIM),
				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
	kmsan_leave_runtime();
}

int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages,
				   unsigned int page_shift, gfp_t gfp_mask)
{
	unsigned long shadow_start, origin_start, shadow_end, origin_end;
	struct page **s_pages, **o_pages;
	int nr, mapped, err = 0;

	if (!kmsan_enabled)
		return 0;

	shadow_start = vmalloc_meta((void *)start, KMSAN_META_SHADOW);
	shadow_end = vmalloc_meta((void *)end, KMSAN_META_SHADOW);
	if (!shadow_start)
		return 0;

	nr = (end - start) / PAGE_SIZE;
	s_pages = kzalloc_objs(*s_pages, nr, gfp_mask);
	o_pages = kzalloc_objs(*o_pages, nr, gfp_mask);
	if (!s_pages || !o_pages) {
		err = -ENOMEM;
		goto ret;
	}
	for (int i = 0; i < nr; i++) {
		struct page_metadata meta = get_page_metadata(pages[i]);

		s_pages[i] = meta.shadow;
		o_pages[i] = meta.origin;
	}
	prot = PAGE_KERNEL;

	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
	origin_end = vmalloc_meta((void *)end, KMSAN_META_ORIGIN);
	kmsan_enter_runtime();
	mapped = __vmap_pages_range_noflush(shadow_start, shadow_end, prot,
					    s_pages, page_shift);
	kmsan_leave_runtime();
	if (mapped) {
		err = mapped;
		goto ret;
	}
	kmsan_enter_runtime();
	mapped = __vmap_pages_range_noflush(origin_start, origin_end, prot,
					    o_pages, page_shift);
	kmsan_leave_runtime();
	if (mapped) {
		err = mapped;
		goto ret;
	}
	flush_tlb_kernel_range(shadow_start, shadow_end);
	flush_tlb_kernel_range(origin_start, origin_end);
	flush_cache_vmap(shadow_start, shadow_end);
	flush_cache_vmap(origin_start, origin_end);

ret:
	kfree(s_pages);
	kfree(o_pages);
	return err;
}

/* Allocate metadata for pages allocated at boot time. */
void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
{
	struct page *shadow_p, *origin_p;
	void *shadow, *origin;
	struct page *page;
	u64 size;

	start = (void *)PAGE_ALIGN_DOWN((u64)start);
	size = PAGE_ALIGN((u64)end - (u64)start);
	shadow = memblock_alloc_or_panic(size, PAGE_SIZE);
	origin = memblock_alloc_or_panic(size, PAGE_SIZE);

	for (u64 addr = 0; addr < size; addr += PAGE_SIZE) {
		page = virt_to_page_or_null((char *)start + addr);
		shadow_p = virt_to_page((char *)shadow + addr);
		set_no_shadow_origin_page(shadow_p);
		origin_p = virt_to_page((char *)origin + addr);
		set_no_shadow_origin_page(origin_p);
		set_page_metadata(page, (struct page_metadata) {
			.shadow = shadow_p,
			.origin = origin_p,
		});
	}
}

void kmsan_setup_meta(struct page *page, struct page *shadow,
		      struct page *origin, int order)
{
	for (int i = 0; i < (1 << order); i++) {
		set_no_shadow_origin_page(&shadow[i]);
		set_no_shadow_origin_page(&origin[i]);
		set_page_metadata(&page[i], (struct page_metadata) {
			.shadow = &shadow[i],
			.origin = &origin[i],
		});
	}
}
