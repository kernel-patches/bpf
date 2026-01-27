/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <common.h>
#include <asan.h>
#include <bump.h>

#include "selftest.h"

#define ST_MAX_PAGES 8

#define PAGE_SHIFT __builtin_ctz(__PAGE_SIZE)

#define ST_MAX_BYTES (ST_MAX_PAGES * __PAGE_SIZE)
#define ST_BYTES_MAX_SHIFT __builtin_ctz(ST_MAX_BYTES)

#define ST_MIN_ALIGN_SHIFT (7)
#define ST_MAX_ALIGN_SHIFT (ST_BYTES_MAX_SHIFT - 2)

#define ST_CYCLES 5

#define ST_PATTERN1 0xAA
#define ST_PATTERN2 0x55

static inline void st_memset(void __arena *mem, u8 byte, size_t size)
{
	u8 __arena *bytes = (u8 __arena *)mem;
	int i;

	bpf_for(i, 0, size) {
		bytes[i] = byte;
	}
}

static inline bool st_isset(void __arena *mem, u8 byte, size_t size)
{
	u8 __arena *bytes = (u8 __arena *)mem;
	int i;

	for (i = 0; i < size && can_loop; i++) {
		if (bytes[i] != byte)
			return false;
	}

	return true;
}

/*
 * Defining oft-repeated snippets as macros to avoid having to propagate
 * errors to the caller. Both GCC and Clang support statement expressions.
 */

#define ALLOC_OR_FAIL(bytes, alignment)                                 \
	({                                                              \
		void __arena *mem;                                      \
		mem = bump_alloc((bytes), (alignment));                 \
		if (!mem) {                                             \
			bpf_printk("%s:%d bump_alloc failed", __func__, \
				   __LINE__);                           \
			bump_destroy();                                 \
			return -ENOMEM;                                 \
		}                                                       \
		mem;                                                    \
	})

#define INIT_OR_FAIL(bytes)                                             \
	do {                                                            \
		if (bump_init(((bytes) / __PAGE_SIZE))) {			\
			bpf_printk("%s:%d bump_init failed", __func__,	\
				   __LINE__);                           \
			return -ENOMEM;                                 \
		}                                                       \
	} while (0)

#define CHECK_OR_FAIL(mem, val, size)                                \
	do {                                                         \
		if (!st_isset((mem), (val), (size))) {                \
			bpf_printk("%s:%d val %d missing", __func__, \
				   __LINE__);                        \
			return -EINVAL;                              \
		}                                                    \
	} while (0)

#define CMP_OR_FAIL(mem1, mem2, size)                                \
	do {                                                         \
		if (st_memcmp((mem1), (mem2), (size))) {             \
			bpf_printk("%s:%d regions differ", __func__, \
				   __LINE__);                        \
			return -EINVAL;                              \
		}                                                    \
	} while (0)

#define ALIGNED_OR_FAIL(mem, alignment)                                 \
	do {                                                            \
		if ((u64)(mem) & ((alignment) - 1)) {                   \
			bpf_printk("%s:%d invalid alignment", __func__, \
				   __LINE__);                           \
			return -EINVAL;                                 \
		}                                                       \
	} while (0)

/*
 * Basic test: 
 *
 * - Create the allocator
 * - Make a single allocation,
 * - Ensure proper alignment
 * - Ensure allocation succeeds and values are all 0s.
 * - Destroy the allocator. Ensure the allocator returns
 * zeroed out memory.
 */
static int bump_selftest_alloc_single(u64 bytes, u64 alignment)
{
	u8 __arena *barray;
	void __arena *mem;
	int i;

	for (i = 0; i < ST_CYCLES && can_loop; i++) {
		INIT_OR_FAIL(bytes);

		mem = ALLOC_OR_FAIL(bytes, alignment);

		/* Alignment is assumed to be 2^n. */
		ALIGNED_OR_FAIL(mem, alignment);

		barray = (u8 __arena *)mem;
		CHECK_OR_FAIL(barray, 0, bytes);

		/* Check whether we're touching unallocated memory. */
		st_memset(barray, ST_PATTERN1, bytes);
		CHECK_OR_FAIL(barray, ST_PATTERN1, bytes);

		bump_destroy();
	}

	return 0;
}

__weak
int bump_selftest_alloc_multiple(u64 bytes, u64 alignment)
{
	void __arena *mem1, *mem2;
	int ret;

	/* Initialize the allocator */
	ret = bump_init(ST_MAX_PAGES);
	if (ret) {
		bpf_printk("bump_init failed with %d", ret);
		return ret;
	}

	mem1 = ALLOC_OR_FAIL(bytes, alignment);
	st_memset(mem1, ST_PATTERN1, bytes);

	mem2 = ALLOC_OR_FAIL(bytes, alignment);
	st_memset(mem2, ST_PATTERN2, bytes);

	ALIGNED_OR_FAIL(mem1, alignment);
	ALIGNED_OR_FAIL(mem2, alignment);

	/* Verify first block still has pattern1 */
	CHECK_OR_FAIL(mem1, ST_PATTERN1, bytes);
	CHECK_OR_FAIL(mem2, ST_PATTERN2, bytes);

	bump_destroy();
	return 0;
}

__weak
int bump_selftest_alloc_aligned(void)
{
	void __arena *mem;
	u64 alignment;
	int round;

	INIT_OR_FAIL(ST_MAX_PAGES * __PAGE_SIZE);

	/* 
	 * Allocate 1 byte at a time to test allocator alignment. 
	 * Test ascending and descending allocation orders.
	 */
	for (round = 0; round < 2 && can_loop; round++) {
		for (alignment = 1; alignment <= __PAGE_SIZE && can_loop;
		     alignment <<= 1) {
			mem = ALLOC_OR_FAIL(1, alignment);
			ALIGNED_OR_FAIL(mem, alignment);
		}

		for (alignment = __PAGE_SIZE; alignment >= 1 && can_loop;
		     alignment >>= 1) {
			mem = ALLOC_OR_FAIL(1, alignment);
			ALIGNED_OR_FAIL(mem, alignment);
		}
	}

	bump_destroy();

	return 0;
}

__weak
int bump_selftest_alloc_exhaustion(u64 bytes, u64 alignment)
{
	size_t allocs = bytes / alignment;
	void __arena *mem;
	int i;

	INIT_OR_FAIL(ST_MAX_PAGES * __PAGE_SIZE);

	if (bump_memlimit(bytes)) {
		bpf_printk("%s:%d bump_memlimit failed", __func__,
			   __LINE__);
		return -EINVAL;
	}

	/* Make an unfullfilable allocation. */
	mem = bump_alloc(bytes + 1, 1);
	if (mem) {
		bpf_printk("%s:%d bump_alloc succeeded", __func__,
			   __LINE__);
		bump_destroy();
		return -EINVAL;
	}

	/*
	 * Amounts to allocations of size alignment, but also
	 * checks that alignment padding is properly accounted for.
	 */
	for (i = 0; i < allocs && can_loop; i++)
		ALLOC_OR_FAIL(1, alignment);

	/* Even a single byte allocation should fail. */
	mem = bump_alloc(1, alignment);
	if (mem) {
		bpf_printk("%s:%d bump_alloc succeeded", __func__,
			   __LINE__);
		bump_destroy();
		return -EINVAL;
	}

	bump_destroy();
	return 0;
}

#define BUMP_ALLOC_SELFTEST(suffix, ...) \
	ALLOC_SELFTEST(bump_selftest_##suffix, __VA_ARGS__)


SEC("syscall")
int bump_selftest(void)
{
	int shift, ashift;
	u64 alignment;
	u64 bytes;

	/* Each test manages its own allocator lifecycle. */

	bpf_for(shift, PAGE_SHIFT, ST_BYTES_MAX_SHIFT + 1) {
		bytes = 1ULL << shift;
		bpf_for(ashift, PAGE_SHIFT, shift + 1) {
			alignment = 1ULL << ashift;
			BUMP_ALLOC_SELFTEST(alloc_single, bytes, alignment);
			BUMP_ALLOC_SELFTEST(alloc_multiple, bytes, alignment);
		}
	}

	BUMP_ALLOC_SELFTEST(alloc_aligned);

	bytes = 1ULL << ST_BYTES_MAX_SHIFT;
	bpf_for(ashift, ST_MIN_ALIGN_SHIFT, ST_MAX_ALIGN_SHIFT + 1) {
		alignment = 1ULL << ashift;
		BUMP_ALLOC_SELFTEST(alloc_exhaustion, bytes, alignment);
	}

	return 0;
}

__weak char _license[] SEC("license") = "GPL";
