// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test_global_map_resize.skel.h"
#include "test_progs.h"

static void run_program(void)
{
	(void)syscall(__NR_getpid);
}

static int setup(struct test_global_map_resize **skel)
{
	if (!skel)
		return -1;

	*skel = test_global_map_resize__open();
	if (!ASSERT_OK_PTR(skel, "test_global_map_resize__open"))
		return -1;

	(*skel)->rodata->pid = getpid();

	return 0;
}

static void teardown(struct test_global_map_resize **skel)
{
	if (skel && *skel)
		test_global_map_resize__destroy(*skel);
}

static int resize_test(struct test_global_map_resize *skel,
		__u32 element_sz, __u32 desired_sz)
{
	int ret = 0;
	struct bpf_map *map;
	__u32 initial_sz, actual_sz;
	size_t nr_elements;
	int *initial_val;
	size_t initial_val_sz;

	map = skel->maps.data_my_array;

	initial_sz = bpf_map__value_size(map);
	ASSERT_EQ(initial_sz, element_sz, "initial size");

	/* round up desired size to align with element size */
	desired_sz = roundup(desired_sz, element_sz);
	ret = bpf_map__set_value_size(map, desired_sz);
	if (!ASSERT_OK(ret, "bpf_map__set_value_size"))
		return ret;

	/* refresh map pointer to avoid invalidation issues */
	map = skel->maps.data_my_array;

	actual_sz = bpf_map__value_size(map);
	ASSERT_EQ(actual_sz, desired_sz, "resize");

	/* set the expected number of elements based on the resized array */
	nr_elements = roundup(actual_sz, element_sz) / element_sz;
	skel->rodata->n = nr_elements;

	/* create array for initial map value */
	initial_val_sz = element_sz * nr_elements;
	initial_val = malloc(initial_val_sz);
	if (!ASSERT_OK_PTR(initial_val, "malloc initial_val")) {
		ret = -ENOMEM;

		goto cleanup;
	}

	/* fill array with ones */
	for (int i = 0; i < nr_elements; ++i)
		initial_val[i] = 1;

	/* set initial value */
	ASSERT_EQ(initial_val_sz, actual_sz, "initial value size");

	ret = bpf_map__set_initial_value(map, initial_val, initial_val_sz);
	if (!ASSERT_OK(ret, "bpf_map__set_initial_val"))
		goto cleanup;

	ret = test_global_map_resize__load(skel);
	if (!ASSERT_OK(ret, "test_global_map_resize__load"))
		goto cleanup;

	ret = test_global_map_resize__attach(skel);
	if (!ASSERT_OK(ret, "test_global_map_resize__attach"))
		goto cleanup;

	/* run the bpf program which will sum the contents of the array */
	run_program();

	if (!ASSERT_EQ(skel->bss->sum, nr_elements, "sum"))
		goto cleanup;

cleanup:
	if (initial_val)
		free(initial_val);

	return ret;
}

static void global_map_resize_aligned_subtest(void)
{
	struct test_global_map_resize *skel;
	const __u32 element_sz = (__u32)sizeof(int);
	const __u32 desired_sz = (__u32)sysconf(_SC_PAGE_SIZE) * 2;

	/* preliminary check that desired_sz aligns with element_sz */
	if (!ASSERT_EQ(desired_sz % element_sz, 0, "alignment"))
		return;

	if (setup(&skel))
		goto teardown;

	if (resize_test(skel, element_sz, desired_sz))
		goto teardown;

teardown:
	teardown(&skel);
}

static void global_map_resize_roundup_subtest(void)
{
	struct test_global_map_resize *skel;
	const __u32 element_sz = (__u32)sizeof(int);
	/* set desired size a fraction of element size beyond an aligned size */
	const __u32 desired_sz = (__u32)sysconf(_SC_PAGE_SIZE) * 2 + element_sz / 2;

	/* preliminary check that desired_sz does NOT align with element_sz */
	if (!ASSERT_NEQ(desired_sz % element_sz, 0, "alignment"))
		return;

	if (setup(&skel))
		goto teardown;

	if (resize_test(skel, element_sz, desired_sz))
		goto teardown;

teardown:
	teardown(&skel);
}

static void global_map_resize_invalid_subtest(void)
{
	int err;
	struct test_global_map_resize *skel;
	struct bpf_map *map;
	const __u32 desired_sz = 8192;

	if (setup(&skel))
		goto teardown;

	/* attempt to resize a global datasec map which is an array
	 * BUT is with a var in same datasec
	 */
	map = skel->maps.data_my_array_and_var;
	err = bpf_map__set_value_size(map, desired_sz);
	if (!ASSERT_EQ(err, -EINVAL, "bpf_map__set_value_size"))
		goto teardown;

	/* attempt to resize a global datasec map which is NOT an array */
	map = skel->maps.data_my_non_array;
	err = bpf_map__set_value_size(map, desired_sz);
	if (!ASSERT_EQ(err, -EINVAL, "bpf_map__set_value_size"))
		goto teardown;

teardown:
	teardown(&skel);
}

void test_global_map_resize(void)
{
	if (test__start_subtest("global_map_resize_aligned"))
		global_map_resize_aligned_subtest();

	if (test__start_subtest("global_map_resize_roundup"))
		global_map_resize_roundup_subtest();

	if (test__start_subtest("global_map_resize_invalid"))
		global_map_resize_invalid_subtest();
}
