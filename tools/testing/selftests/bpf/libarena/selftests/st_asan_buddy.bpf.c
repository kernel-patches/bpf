// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <common.h>

#include <asan.h>
#include <buddy.h>

#include "selftest.h"


#ifdef BPF_ARENA_ASAN

#include "st_asan_common.h"

private(ST_BUDDY) struct buddy st_buddy_asan;

u64 __arena st_asan_buddy_lock;

static __always_inline int asan_test_buddy_oob_single(size_t alloc_size)
{
	u8 __arena *mem;
	int i;

	ASAN_VALIDATE();

	mem = buddy_alloc(&st_buddy_asan, alloc_size);
	if (!mem) {
		arena_stdout("buddy_alloc failed for size %lu", alloc_size);
		return -ENOMEM;
	}

	ASAN_VALIDATE();

	for (i = zero; i < alloc_size && can_loop; i++) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(false, &mem[i]);
	}

	mem[alloc_size] = 0xba;
	ASAN_VALIDATE_ADDR(true, &mem[alloc_size]);

	buddy_free(&st_buddy_asan, mem);

	return 0;
}

/*
 * Factored out because ASAN_VALIDATE_ADDR is complex enough to cause
 * verification failures if verified with the rest of asan_test_buddy_uaf_single.
 */
__weak int asan_test_buddy_byte(u8 __arena __arg_arena *mem, int i, bool freed)
{
	/* The header in freed blocks doesn't get poisoned. */
	if (freed && BUDDY_HEADER_OFF <= i &&
		i < BUDDY_HEADER_OFF + sizeof(struct buddy_header))
		return 0;

	mem[i] = 0xba;
	ASAN_VALIDATE_ADDR(freed, &mem[i]);

	return 0;
}

__weak int asan_test_buddy_uaf_single(size_t alloc_size)
{
	u8 __arena *mem;
	int ret;
	int i;

	mem = buddy_alloc(&st_buddy_asan, alloc_size);
	if (!mem) {
		arena_stdout("buddy_alloc failed for size %lu", alloc_size);
		return -ENOMEM;
	}

	ASAN_VALIDATE();

	for (i = zero; i < alloc_size && can_loop; i++) {
		ret = asan_test_buddy_byte(mem, i, false);
		if (ret)
			return ret;
	}

	ASAN_VALIDATE();

	buddy_free(&st_buddy_asan, mem);

	for (i = zero; i < alloc_size && can_loop; i++) {
		ret = asan_test_buddy_byte(mem, i, true);
		if (ret)
			return ret;
	}

	return 0;
}

struct buddy_blob {
	volatile u8 mem[48];
	u8 oob;
};

static __always_inline int asan_test_buddy_blob_single(void)
{
	volatile struct buddy_blob __arena *blob;
	const size_t alloc_size = sizeof(struct buddy_blob) - 1;

	blob = buddy_alloc(&st_buddy_asan, alloc_size);
	if (!blob)
		return -ENOMEM;

	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[0]);

	blob->mem[47] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[47]);

	blob->oob = 0;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	buddy_free(&st_buddy_asan, (void __arena *)blob);

	return 0;
}

static __always_inline int asan_test_buddy_oob(void)
{
	size_t sizes[] = {
		7, 8, 17, 18, 64, 256, 317, 512, 1024,
	};
	int ret, i;

	ret = buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_buddy_lock);
	if (ret) {
		arena_stdout("buddy_init failed with %d", ret);
		return ret;
	}

	for (i = zero; i < sizeof(sizes) / sizeof(sizes[0]) && can_loop; i++) {
		ret = asan_test_buddy_oob_single(sizes[i]);
		if (ret) {
			arena_stdout("%s:%d Failed for size %lu", __func__,
				   __LINE__, sizes[i]);
			buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

__weak int asan_test_buddy_uaf(void)
{
	size_t sizes[] = { 16, 32, 64, 128, 256, 512, 128, 1024, 16384 };
	int ret, i;

	ret = buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_buddy_lock);
	if (ret) {
		arena_stdout("buddy_init failed with %d", ret);
		return ret;
	}

	for (i = zero; i < sizeof(sizes) / sizeof(sizes[0]) && can_loop; i++) {
		ret = asan_test_buddy_uaf_single(sizes[i]);
		if (ret) {
			arena_stdout("%s:%d Failed for size %lu", __func__,
				   __LINE__, sizes[i]);
			buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

static __always_inline int asan_test_buddy_blob(void)
{
	const int iters = 10;
	int ret, i;

	ret = buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_buddy_lock);
	if (ret) {
		arena_stdout("buddy_init failed with %d", ret);
		return ret;
	}

	for (i = zero; i < iters && can_loop; i++) {
		ret = asan_test_buddy_blob_single();
		if (ret) {
			arena_stdout("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

SEC("syscall")
int asan_test_buddy(void)
{
	int ret;

	ret = asan_test_buddy_oob();
	if (ret) {
		arena_stdout("%s:%d OOB test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_buddy_uaf();
	if (ret) {
		arena_stdout("%s:%d UAF test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_buddy_blob();
	if (ret) {
		arena_stdout("%s:%d blob test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

#else

SEC("syscall")
int asan_test_buddy(void)
{
	return -EOPNOTSUPP;
}

#endif /* BPF_ARENA_ASAN */

__weak char _license[] SEC("license") = "GPL";
