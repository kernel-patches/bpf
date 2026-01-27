/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

/*
 * Static allocation module used to allocate arena memory for
 * whose lifetime is that of the BPF program. Data is rarely
 * allocated, mostly at program init, and never freed. The
 * memory returned by this code is typeless so it avoids us
 * having to define an allocator for each type.
 */

#include <common.h>
#include <asan.h>
#include <bump.h>

/* Maximum memory that can be allocated by the arena. */
#define ARENA_MAX_MEMORY (1ULL << 20)

private(STATIC_ALLOC_LOCK) struct bpf_spin_lock static_lock;

private(STATIC_ALLOC) struct bump bump;

const s8 STATIC_POISON_UNINIT = 0xff;

__weak u64 bump_alloc_internal(size_t bytes, size_t alignment)
{
	void __arena *memory;
	size_t	alloc_bytes;
	size_t	alloc_pages;
	void __arena *ptr;
	size_t padding;
	size_t ind;
	u64 addr;

	/* 
	 * Allocated addresses must be aligned to the nearest granule,
	 * and since we're stack allocating this implies that allocations
	 * sizes are also aligned.
	 */
	alignment = round_up(alignment, 1 << ASAN_SHADOW_SHIFT);

	bpf_spin_lock(&static_lock);

	/* Round up the current offset. */
	addr = (__u64)bump.memory + bump.off;

	padding	= round_up(addr, alignment) - addr;
	alloc_bytes = bytes + padding;

	if (alloc_bytes > bump.max_contig_bytes) {
		bpf_spin_unlock(&static_lock);
		bpf_printk("invalid request %ld, max is %ld\n", alloc_bytes,
			   bump.max_contig_bytes);
		return (u64)NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 */
	if (bump.off + alloc_bytes > bump.max_contig_bytes) {
		if (bump.cur_memusage + bump.max_contig_bytes >
		    bump.lim_memusage) {
			bpf_spin_unlock(&static_lock);
			bpf_printk("allocator memory limit exceeded");
			return (u64)NULL;
		}

		alloc_pages = bump.max_contig_bytes / __PAGE_SIZE;

		memory = bpf_arena_alloc_pages(&arena, NULL, alloc_pages,
						    NUMA_NO_NODE, 0);
		if (!memory) {
			bpf_spin_unlock(&static_lock);
			bpf_printk("failed to allocate memory");
			return (u64)NULL;
		}

		/* Keep a list of allocated blocks to free on allocator destruction. */
		ind = bump.past_allocs_ind++ % BUMP_ALLOCS_MAX;
		bump.past_allocs[ind] = memory;

		asan_poison(memory, STATIC_POISON_UNINIT, bump.max_contig_bytes);

		/*
		 * Switch to new memory block, reset offset,
		 * and recalculate base address.
		 */
		bump.memory = memory;
		bump.off = 0;
		addr = (__u64)bump.memory;

		/*
		 * We changed the base address. Recompute the padding.
		 */
		padding	= round_up(addr, alignment) - addr;
		alloc_bytes = bytes + padding;

		bump.cur_memusage += bump.max_contig_bytes;
	}

	ptr = (void __arena *)(addr + padding);
	asan_unpoison(ptr, bytes);

	bump.off += alloc_bytes;

	bpf_spin_unlock(&static_lock);

	return (u64)ptr;
}

__weak int bump_destroy(void)
{
	size_t alloc_pages = bump.max_contig_bytes / __PAGE_SIZE;
	void __arena *mem;
	size_t lim;
	int i;

	/* Free all allocated blocks. */

	lim = bump.past_allocs_ind < BUMP_ALLOCS_MAX ? 
		bump.past_allocs_ind : BUMP_ALLOCS_MAX;

	for (i = 0; i < lim && can_loop; i++) {
		mem = bump.past_allocs[i];
		asan_unpoison(mem, bump.max_contig_bytes);
		bpf_arena_free_pages(&arena, mem, alloc_pages);
	}

	return 0;
}

__weak int bump_init(size_t contig_pages)
{
	size_t contig_bytes = contig_pages * __PAGE_SIZE;
	void __arena *memory;
	size_t ind;
	int ret;

	memory = bpf_arena_alloc_pages(&arena, NULL, contig_pages, NUMA_NO_NODE,
				       0);
	if (!memory) {
		bpf_printk("Failed to allocate %d pages", contig_pages);
		return -ENOMEM;
	}

	ret = asan_poison(memory, STATIC_POISON_UNINIT, contig_bytes);
	if (ret)
		bpf_printk("Error %d: by poisoning", ret);

	bump.max_contig_bytes = contig_bytes;
	bump.off = 0;
	bump.memory = memory;
	bump.lim_memusage = ARENA_MAX_MEMORY;
	bump.cur_memusage = contig_bytes;

	ind = bump.past_allocs_ind++ % BUMP_ALLOCS_MAX;
	bump.past_allocs[ind] = memory;

	return 0;
}

__weak int bump_memlimit(u64 lim_memusage)
{
	bpf_spin_lock(&static_lock);

	if (lim_memusage > BUMP_ALLOCS_MAX * bump.max_contig_bytes)
		goto error;

	/* We always allocate at a page granularity. */
	if (lim_memusage % __PAGE_SIZE)
		goto error;

	/* Have we already overshot the limit? */
	if (lim_memusage < bump.cur_memusage)
		goto error;

	bump.lim_memusage = lim_memusage;

	bpf_spin_unlock(&static_lock);

	return 0;

error:
	bpf_spin_unlock(&static_lock);

	return -EINVAL;
}

__weak char _license[] SEC("license") = "GPL";
