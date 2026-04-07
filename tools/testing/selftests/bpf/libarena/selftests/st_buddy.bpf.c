// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <common.h>

#include <asan.h>
#include <buddy.h>

#include "selftest.h"


private(ST_BUDDY) struct buddy st_buddy;
static u64 __arena st_buddy_lock;

struct segarr_entry {
	u8 __arena *block;
	size_t sz;
	u8 poison;
};

typedef struct segarr_entry __arena segarr_entry_t;

#define SEGARRLEN (512)
static struct segarr_entry __arena segarr[SEGARRLEN];
static void __arena *ptrs[17];
size_t __arena alloc_sizes[] = { 3, 17, 1025, 129, 16350, 333, 9, 517 };
size_t __arena alloc_multiple_sizes[] = { 3, 17, 1025, 129, 16350, 333, 9, 517, 2099 };
size_t __arena alloc_free_sizes[] = { 3, 17, 64, 129, 256, 333, 512, 517 };
size_t __arena alignment_sizes[] = { 1, 3, 7, 8, 9, 15, 16, 17, 31,
				     32, 64, 100, 128, 255, 256, 512, 1000 };

static int test_buddy_create(void)
{
	const int iters = 10;
	int ret, i;

	for (i = zero; i < iters && can_loop; i++) {
		ret = buddy_init(
			&st_buddy, (arena_spinlock_t __arena *)&st_buddy_lock);
		if (ret)
			return ret;

		ret = buddy_destroy(&st_buddy);
		if (ret)
			return ret;
	}

	return 0;
}

static int test_buddy_alloc(void)
{
	void __arena *mem;
	int ret, i;

	for (i = zero; i < 8 && can_loop; i++) {
		ret = buddy_init(
			&st_buddy, (arena_spinlock_t __arena *)&st_buddy_lock);
		if (ret)
			return ret;

		mem = buddy_alloc(&st_buddy, alloc_sizes[i]);
		if (!mem) {
			buddy_destroy(&st_buddy);
			return -ENOMEM;
		}

		buddy_destroy(&st_buddy);
	}

	return 0;
}

static int test_buddy_alloc_free(void)
{
	const int iters = 800;
	void __arena *mem;
	int ret, i;

	ret = buddy_init(&st_buddy,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	for (i = zero; i < iters && can_loop; i++) {
		mem = buddy_alloc(&st_buddy, alloc_free_sizes[(i * 5) % 8]);
		if (!mem) {
			buddy_destroy(&st_buddy);
			return -ENOMEM;
		}

		buddy_free(&st_buddy, mem);
	}

	buddy_destroy(&st_buddy);

	return 0;
}

static int test_buddy_alloc_multiple(void)
{
	int ret, j;
	u32 i, idx;
	u8 __arena *mem;
	size_t sz;
	u8 poison;

	ret = buddy_init(&st_buddy,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	/*
	 * Cycle through each size, allocating an entry in the
	 * segarr. Continue for SEGARRLEN iterations. For every
	 * allocation write down the size, use the current index
	 * as a poison value, and log it with the pointer in the
	 * segarr entry. Use the poison value to poison the entire
	 * allocated memory according to the size given.
	 */
	idx = 0;
	for (i = zero; i < SEGARRLEN && can_loop; i++) {
		sz = alloc_multiple_sizes[i % 9];
		poison = (u8)i;

		mem = buddy_alloc(&st_buddy, sz);
		if (!mem) {
			buddy_destroy(&st_buddy);
			arena_stdout("%s:%d", __func__, __LINE__);
			return -ENOMEM;
		}

		segarr[i].block = mem;
		segarr[i].sz = sz;
		segarr[i].poison = poison;

		for (j = zero; j < sz && can_loop; j++) {
			mem[j] = poison;
			if (mem[j] != poison) {
				buddy_destroy(&st_buddy);
				return -EINVAL;
			}
		}
	}

	/*
	 * Go to (i * 17) % SEGARRLEN, and free the block pointed to.
	 * Before freeing, check all bytes have the poisoned value
	 * corresponding to the element. If any values are unexpected,
	 * return an error. Skip some elements to test destroying the
	 * buddy allocator while data is still allocated.
	 */
	for (i = 10; i < SEGARRLEN && can_loop; i++) {
		idx = (i * 17) % SEGARRLEN;

		mem = segarr[idx].block;
		sz = segarr[idx].sz;
		poison = segarr[idx].poison;

		for (j = zero; j < sz && can_loop; j++) {
			if (mem[j] != poison) {
				buddy_destroy(&st_buddy);
				arena_stdout("%s:%d %lx %u vs %u", __func__,
					   __LINE__, &mem[j], mem[j], poison);
				return -EINVAL;
			}
		}

		buddy_free(&st_buddy, mem);
	}

	buddy_destroy(&st_buddy);

	return 0;
}

static int test_buddy_alignment(void)
{
	int ret, i;

	ret = buddy_init(&st_buddy,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	/* Allocate various sizes and check alignment */
	for (i = zero; i < 17 && can_loop; i++) {
		ptrs[i] = buddy_alloc(&st_buddy, alignment_sizes[i]);
		if (!ptrs[i]) {
			arena_stdout("alignment test: alloc failed for size %lu",
				   alignment_sizes[i]);
			buddy_destroy(&st_buddy);
			return -ENOMEM;
		}

		/* Check 8-byte alignment */
		if ((u64)ptrs[i] & 0x7) {
			arena_stdout(
				"alignment test: ptr %llx not 8-byte aligned (size %lu)",
				(u64)ptrs[i], alignment_sizes[i]);
			buddy_destroy(&st_buddy);
			return -EINVAL;
		}
	}

	/* Free all allocations */
	for (i = zero; i < 17 && can_loop; i++) {
		buddy_free(&st_buddy, ptrs[i]);
	}

	buddy_destroy(&st_buddy);

	return 0;
}

#define BUDDY_ALLOC_SELFTEST(suffix) ALLOC_SELFTEST(test_buddy_##suffix)

SEC("syscall")
__weak int test_buddy(void)
{
	BUDDY_ALLOC_SELFTEST(create);
	BUDDY_ALLOC_SELFTEST(alloc);
	BUDDY_ALLOC_SELFTEST(alloc_free);
	BUDDY_ALLOC_SELFTEST(alloc_multiple);
	BUDDY_ALLOC_SELFTEST(alignment);

	return 0;
}

__weak char _license[] SEC("license") = "GPL";
