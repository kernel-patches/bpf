/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <common.h>

#include <asan.h>
#include <bump.h>

#include "selftest.h"

#ifdef BPF_ARENA_ASAN

#include "st_asan_common.h"

int asan_test_bump_blob_one(void)
{
	volatile struct blob __arena *blob;
	const size_t alignment = 1;

	blob = bump_alloc(sizeof(blob) - 1, alignment);
	if (!blob)
		return -ENOMEM;

	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[0]);

	blob->oob = 0;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	blob = (volatile struct blob __arena *)&blob->oob;
	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(true, &blob->mem[0]);

	blob->oob = 4;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	/*
	 * Go even further, cast the OOB variable into
	 * another struct blob and access its own oob.
	 */
	blob = (volatile struct blob __arena *)&blob->oob;
	blob->oob = 5;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	return 0;
}

int asan_test_bump_blob(void)
{
	const int iters = 20;
	int ret, i;

	ret = bump_init(ST_PAGES);
	if (ret) {
		bpf_printk("bump_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_bump_blob_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}
	}

	bump_destroy();

	ASAN_VALIDATE();

	return 0;
}

int asan_test_bump_array_one(void)
{
	size_t bytes = 37;
	size_t overrun = 13;
	size_t alignment = 1;
	char __arena *mem;
	int i;

	mem = bump_alloc(sizeof(*mem) * bytes, alignment);
	if (!mem)
		return -ENOMEM;

	for (i = 0; i < bytes + overrun && can_loop; i++) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(i >= bytes, &mem[i]);
	}

	ASAN_VALIDATE();

	return 0;
}

int asan_test_bump_array(void)
{
	const size_t iters = 20;
	int ret, i;

	ret = bump_init(ST_PAGES);
	if (ret) {
		bpf_printk("bump_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_bump_array_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}
	}

	bump_destroy();

	return 0;
}

int asan_test_bump_all(void)
{
	const int iters = 50;
	int ret, i;

	ret = bump_init(ST_PAGES);
	if (ret) {
		bpf_printk("bump_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_bump_array_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}

		ret = asan_test_bump_blob_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}
	}

	bump_destroy();

	return 0;
}

SEC("syscall")
int asan_test_bump(void)
{
	int ret;

	ret = asan_test_bump_blob();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_bump_array();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_bump_all();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

#else

SEC("syscall")
int asan_test_bump(void)
{
	return -EOPNOTSUPP;
}

#endif /* BPF_ARENA_ASAN */

__weak char _license[] SEC("license") = "GPL";
