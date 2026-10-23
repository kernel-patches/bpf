// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#pragma once

enum buddy_consts {
	/*
	 * Minimum allocation is 1 << BUDDY_MIN_ALLOC_SHIFT.
	 * Larger sizes increase internal fragmentation, but smaller
	 * sizes increase the space overhead of the block metadata.
	 */
	BUDDY_MIN_ALLOC_SHIFT	= 4,
	BUDDY_MIN_ALLOC_BYTES	= 1 << BUDDY_MIN_ALLOC_SHIFT,

	/*
	 * How many orders the buddy allocator can serve. Minimum block
	 * size is 1 << BUDDY_MIN_ALLOC_SHIFT, maximum block size is
	 * 1 << (BUDDY_MIN_ALLOC_SHIFT + BUDDY_CHUNK_NUM_ORDERS - 1):
	 * Each block has size 1 << BUDDY_MIN_ALLOC_SHIFT, and the
	 * allocation orders are in [0, BUDDY_CHUNK_NUM_ORDERS).
	 * We keep two blocks of the maximum size to retain the
	 * property in the code that all blocks have a buddy.
	 * Higher values increase the maximum allocation size,
	 * but also the size of the metadata for each block.
	 */
	BUDDY_CHUNK_NUM_ORDERS	= 1 << 4,
	BUDDY_CHUNK_BYTES	= BUDDY_MIN_ALLOC_BYTES << (BUDDY_CHUNK_NUM_ORDERS),

	/* Offset of the buddy header within a free block, see buddy.bpf.c for details */
	BUDDY_HEADER_OFF	= 8,

	/* The maximum number of blocks a chunk may have to track. */
	BUDDY_CHUNK_ITEMS	= 1 << (BUDDY_CHUNK_NUM_ORDERS),
	BUDDY_CHUNK_OFFSET_MASK	= BUDDY_CHUNK_BYTES - 1,

	/*
	 * Alignment for chunk allocations based on bpf_arena_alloc_pages.
	 * The arena allocation kfunc does not have an alignment argument,
	 * but that is required for all block calculations in the chunk to
	 * work.
	 */
	BUDDY_VADDR_OFFSET	= BUDDY_CHUNK_BYTES,

	/* Total arena virtual address space the allocator can consume. */
	BUDDY_VADDR_SIZE	= BUDDY_CHUNK_BYTES << 10
};

struct buddy_header {
	u32 prev_index;	/* "Pointer" to the previous available allocation of the same size. */
	u32 next_index; /* Same for the next allocation. */
};

struct buddy_deferred_free;

/*
 * We bring memory into the allocator 1 MiB at a time.
 */
struct buddy_chunk {
	/* The order of the current allocation for a item. 4 bits per order. */
	u8		orders[BUDDY_CHUNK_ITEMS / 2];
	/*
	 * Bit to denote whether chunk is allocated. Size of the allocated/free
	 * chunk found from the orders array.
	 */
	u8		allocated[BUDDY_CHUNK_ITEMS / 8];
	/* Freelists for O(1) allocation. */
	u64		freelists[BUDDY_CHUNK_NUM_ORDERS];
	struct buddy_chunk __arena	*next;
};

/* Constants related to the buddy allocator's object caches. */
enum buddy_cache_consts {
	/*
	 * Do not cache larger allocations to avoid excessive
	 * memory consumption from the per-cpu lists.
	 */
	BUDDY_CACHE_NUM_ORDERS = 1 << 3,

	/*
	 * Just like arena spinlocks, hardcode percpu state to a maximum number of CPUs.
	 * Since arena spinlocks are a hard dependency, use the exact same limit.
	 */
	BUDDY_CACHE_MAX_CPUS = 1024,

	/* Objects moved to and from the buddy allocator at once, as an order. */
	BUDDY_CACHE_BATCH_ORDER = 3,
	BUDDY_CACHE_BATCH_SIZE = 1 << BUDDY_CACHE_BATCH_ORDER,

	/*
	 * Objects retained locally for each allocation order.
	 */
	BUDDY_CACHE_CAPACITY = BUDDY_CACHE_BATCH_SIZE * 2,

	/* Number of objects shared between per-CPU caches for each order. */
	BUDDY_TRANSFER_CAPACITY = BUDDY_CACHE_BATCH_SIZE * 8,
};

struct buddy_cache_order {
	u32 elems;
	u32 __pad;
	void __arena *objects[BUDDY_CACHE_CAPACITY];
} __attribute__((aligned(64)));

/* Dynamically allocated packed per-CPU slot slab. */
struct buddy_cache {
	/* Claimed by an in-flight cache operation on this CPU. */
	unsigned int active;
	struct buddy_cache_order orders[BUDDY_CACHE_NUM_ORDERS];
};

/* Per-order array shared between the per-CPU caches. */
struct buddy_transfer_order {
	arena_spinlock_t lock;
	u32 elems;
	void __arena *objects[BUDDY_TRANSFER_CAPACITY];
} __attribute__((aligned(64)));

struct buddy {
	struct buddy_chunk __arena *first_chunk;		/* Pointer to the chunk linked list. */
	arena_spinlock_t lock;			/* Allocator lock */
	u64 vaddr;				/* Allocation into reserved vaddr */
	struct buddy_cache __arena *percpu[BUDDY_CACHE_MAX_CPUS];
	struct buddy_transfer_order transfer[BUDDY_CACHE_NUM_ORDERS];
	struct buddy_deferred_free __arena *deferred_free;
};

#ifdef __BPF__

int buddy_init(struct buddy __arena *buddy);
int buddy_destroy(struct buddy __arena *buddy);
int buddy_free(struct buddy __arena *buddy, void __arena *free);
int buddy_free_bulk(struct buddy __arena *buddy, void __arena * __arena *addrs,
	size_t naddrs);
void __arena *buddy_alloc(struct buddy __arena *buddy, size_t size);
int buddy_alloc_bulk(struct buddy __arena *buddy, size_t size, size_t norder,
	void __arena * __arena *out);

#endif /* __BPF__  */
