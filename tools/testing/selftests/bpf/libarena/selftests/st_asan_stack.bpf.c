/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <common.h>

#include <asan.h>
#include <stack.h>

#include "selftest.h"

#ifdef BPF_ARENA_ASAN

#include "st_asan_common.h"

#define STACK_PAGES_PER_ALLOC (4)
#define STACK_ALLOCS (4)

/* 
 * Keep this test-related array in BSS to avoid
 * overly burdening the function stack.
 */
u64 __arena stk_blks[STACK_ALLOCS];

/*
 * Spinlock used by the stack allocator.
 */
private(ST_STACK) struct stk st_stack;
u64 __arena st_asan_stack_lock;

static __maybe_unused void stk_blks_dump(void)
{
	int i;

	for (i = 0; i < STACK_ALLOCS && can_loop; i++)
		bpf_printk("[%d] 0x%lx", i, stk_blks[i]);
}

struct qsort_limits {
	int lo;
	int hi;
};

__always_inline void swap(unsigned int i, unsigned int j)
{
	u64 tmp;

	tmp = stk_blks[i];
	stk_blks[i] = stk_blks[j];
	stk_blks[j] = tmp;
}

static __always_inline int qsort_partition(unsigned int lo, unsigned hi)
{
	unsigned int i;
	u64 pivotval;
	int pivot;

	if (lo >= STACK_ALLOCS || hi >= STACK_ALLOCS) {
		bpf_printk("%s:%d invalid lo/hi indices %d/%d", __func__,
			   __LINE__, lo, hi);
		return 0;
	}

	pivotval = stk_blks[hi];
	pivot = lo;

	for (i = lo; i < hi && can_loop; i++) {
		if (stk_blks[i] > pivotval)
			continue;

		swap(i, pivot);
		pivot += 1;
	}

	swap(pivot, hi);

	return pivot;
}

static __always_inline int qsort_stack_blocks(void)
{
	struct qsort_limits stack[STACK_ALLOCS];
	struct qsort_limits limits;
	int stackind = 0;
	int pivot;

	limits = (struct qsort_limits){ 0, STACK_ALLOCS - 1 };
	stack[stackind++] = limits;

	while (stackind > 0 && can_loop) {
		if (stackind <= 0 || stackind > STACK_ALLOCS) {
			bpf_printk("%s:%d invalid stack index %d", __func__,
				   __LINE__, stackind);
			return 0;
		}

		limits = stack[--stackind];
		if (limits.lo >= limits.hi)
			continue;

		pivot = qsort_partition(limits.lo, limits.hi);
		stack[stackind++] = (struct qsort_limits){
			.lo = limits.lo,
			.hi = pivot - 1,
		};

		if (stackind <= 0 || stackind >= STACK_ALLOCS) {
			bpf_printk("%s:%d invalid stack index", __func__,
				   __LINE__);
			return 0;
		}

		stack[stackind++] = (struct qsort_limits){
			.lo = pivot + 1,
			.hi = limits.hi,
		};
	}

	return 0;
}

int asan_test_stack_uaf_oob_single(u8 __arena __arg_arena *alloced,
				   u8 __arena __arg_arena *freed)
{
	const size_t overshoot = 5;
	int i;

	/* Use after free check. */
	stk_free(&st_stack, freed);

	bpf_for(i, 0, __PAGE_SIZE) {
		freed[i] = 0xba;
		ASAN_VALIDATE_ADDR(true, &freed[i]);
	}

	/* 
	 * Out of bounds check. Assuming the blocks before were
	 * allocated consecutively, past the end of the block
	 * the memory is guaranteed to be freed.
	 */
	bpf_for(i, 0, __PAGE_SIZE + overshoot) {
		alloced[i] = 0xba;
		ASAN_VALIDATE_ADDR(i >= __PAGE_SIZE, &alloced[i]);
	}

	return 0;
}

static int asan_sort_stack_blocks()
{
	int i;

	qsort_stack_blocks();

	if (!stk_blks[0]) {
		bpf_printk("NULL stack block pointer");
		return -EINVAL;
	}

	for (i = 1; i < STACK_ALLOCS; i++) {
		if (!stk_blks[i]) {
			bpf_printk("missing block");
			return -EINVAL;
		}

		if (stk_blks[i] != stk_blks[i - 1] + __PAGE_SIZE) {
			bpf_printk("allocations not consecutive");
			return -EINVAL;
		}
	}

	return 0;
}

static __always_inline int asan_test_stack_uaf_oob(void)
{
	u64 base = (u64)(-1);
	const u64 alloc_size = 4096;
	u64 block;
	int ret, i;

	/* Set the stack to support 4KiB allocations. */
	ret = stk_init(&st_stack, (arena_spinlock_t __arena *)&st_asan_stack_lock,
			   alloc_size, STACK_PAGES_PER_ALLOC);
	if (ret) {
		bpf_printk("stk_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, STACK_ALLOCS) {
		block = (u64)stk_alloc(&st_stack);
		if (!block) {
			bpf_printk("allocation %d failed", i);
			return -ENOMEM;
		}

		stk_blks[i] = block;
		base = block < base ? block : base;
	}

	ret = asan_sort_stack_blocks();
	if (ret)
		return ret;

	for (i = 0; i < STACK_ALLOCS && can_loop; i += 2) {
		if (i + 1 >= STACK_ALLOCS)
			break;

		if (stk_blks[i] + alloc_size != stk_blks[i + 1]) {
			bpf_printk("Stack allocations not consecutive");
			return -EINVAL;
		}

		ret = asan_test_stack_uaf_oob_single(
			(u8 __arena *)stk_blks[i],
			(u8 __arena *)stk_blks[i + 1]);
		if (ret)
			return ret;
	}

	stk_destroy(&st_stack);

	return 0;
}

SEC("syscall")
int asan_test_stack(void)
{
	int ret;

	ret = asan_test_stack_uaf_oob();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

#else

SEC("syscall")
int asan_test_stack(void)
{
	return -EOPNOTSUPP;
}

#endif /* BPF_ARENA_ASAN */

__weak char _license[] SEC("license") = "GPL";
