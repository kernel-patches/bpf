/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

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
		bpf_printk("buddy_alloc failed for size %lu", alloc_size);
		return -ENOMEM;
	}

	ASAN_VALIDATE();

	bpf_for(i, 0, alloc_size) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(false, &mem[i]);
	}

	mem[alloc_size] = 0xba;
	ASAN_VALIDATE_ADDR(true, &mem[alloc_size]);

	buddy_free(&st_buddy_asan, mem);

	return 0;
}

static __always_inline int asan_test_buddy_uaf_single(size_t alloc_size)
{
	u8 __arena *mem;
	int i;

	mem = buddy_alloc(&st_buddy_asan, alloc_size);
	if (!mem) {
		bpf_printk("buddy_alloc failed for size %lu", alloc_size);
		return -ENOMEM;
	}

	ASAN_VALIDATE();

	bpf_for(i, 0, alloc_size) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(false, &mem[i]);
	}

	ASAN_VALIDATE();

	buddy_free(&st_buddy_asan, mem);

	bpf_for(i, 0, alloc_size) {
		/* The header doesn't get poisoned. */
		if (BUDDY_HEADER_OFF <= i &&
		    i < BUDDY_HEADER_OFF + sizeof(struct buddy_header))
			continue;

		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(true, &mem[i]);
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
		bpf_printk("buddy_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, 7) {
		ret = asan_test_buddy_oob_single(sizes[i]);
		if (ret) {
			bpf_printk("%s:%d Failed for size %lu", __func__,
				   __LINE__, sizes[i]);
			buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

static __always_inline int asan_test_buddy_uaf(void)
{
	size_t sizes[] = { 16, 32, 64, 128, 256, 512, 128, 1024, 16384 };
	int ret, i;

	ret = buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_buddy_lock);
	if (ret) {
		bpf_printk("buddy_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, 7) {
		ret = asan_test_buddy_uaf_single(sizes[i]);
		if (ret) {
			bpf_printk("%s:%d Failed for size %lu", __func__,
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
		bpf_printk("buddy_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_buddy_blob_single();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
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
		bpf_printk("%s:%d OOB test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_buddy_uaf();
	if (ret) {
		bpf_printk("%s:%d UAF test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_buddy_blob();
	if (ret) {
		bpf_printk("%s:%d blob test failed", __func__, __LINE__);
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
