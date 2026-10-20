// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#pragma once

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

	/*
	 * Items transferred as one batch. This must remain a power of two because
	 * buddy_alloc_bulk() expresses the number of objects as an order.
	 */
	BUDDY_CACHE_BATCH_SIZE = 8,

	/*
	 * Objects retained locally for each allocation order.
	 */
	BUDDY_CACHE_CAPACITY = BUDDY_CACHE_BATCH_SIZE * 2,
};

struct buddy_cache_order {
	u32 elems;
	u32 __pad;
	void __arena *objects[BUDDY_CACHE_CAPACITY];
} __attribute__((aligned(64)));

/* Dynamically allocated packed per-CPU slot slab. */
struct buddy_cache {
	struct buddy_cache_order orders[BUDDY_CACHE_NUM_ORDERS];
};

struct buddy_cache_state {
	struct buddy_cache __arena *percpu[BUDDY_CACHE_MAX_CPUS];
	bool valid;
};

/* Per-CPU guard against nested or preempting cache operations. */

struct __attribute__((aligned(64))) buddy_cache_active {
	unsigned int value;
};
