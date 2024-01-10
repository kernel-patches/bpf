// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */
#include <test_progs.h>
#include "array_elem_test.skel.h"

#include <sys/mman.h>

#define NR_MAP_ELEMS 100

static size_t map_mmap_sz(struct bpf_map *map)
{
	size_t mmap_sz;

	mmap_sz = (size_t)roundup(bpf_map__value_size(map), 8) *
		bpf_map__max_entries(map);
	mmap_sz = roundup(mmap_sz, sysconf(_SC_PAGE_SIZE));

	return mmap_sz;
}

static void *map_mmap(struct bpf_map *map)
{
	return mmap(NULL, map_mmap_sz(map), PROT_READ | PROT_WRITE, MAP_SHARED,
		    bpf_map__fd(map), 0);
}

static void map_munmap(struct bpf_map *map, void *addr)
{
	munmap(addr, map_mmap_sz(map));
}

struct arr_elem_fixture {
	struct array_elem_test *skel;
	int *map_elems;
};

static void setup_fixture(struct arr_elem_fixture *tf, size_t prog_off)
{
	struct array_elem_test *skel;
	struct bpf_program *prog;
	int err;

	skel = array_elem_test__open();
	if (!ASSERT_OK_PTR(skel, "array_elem_test open"))
		return;

	/*
	 * Our caller doesn't know the addr of the program until the skeleton is
	 * opened.  But the offset to the pointer is statically known.
	 */
	prog = *(struct bpf_program**)((__u8*)skel + prog_off);
	bpf_program__set_autoload(prog, true);

	err = array_elem_test__load(skel);
	if (!ASSERT_EQ(err, 0, "array_elem_test load")) {
		array_elem_test__destroy(skel);
		return;
	}

	err = array_elem_test__attach(skel);
	if (!ASSERT_EQ(err, 0, "array_elem_test attach")) {
		array_elem_test__destroy(skel);
		return;
	}

	for (int i = 0; i < NR_MAP_ELEMS; i++) {
		skel->bss->lookup_indexes[i] = i;
		err = bpf_map_update_elem(bpf_map__fd(skel->maps.lookup_again),
					  &i, &i, BPF_ANY);
		ASSERT_EQ(err, 0, "array_elem_test set lookup_again");
	}

	tf->map_elems = map_mmap(skel->maps.arraymap);
	ASSERT_OK_PTR(tf->map_elems, "mmap");

	tf->skel = skel;
}

static void run_test(struct arr_elem_fixture *tf)
{
	tf->skel->bss->target_pid = getpid();
	usleep(1);
}

static void destroy_fixture(struct arr_elem_fixture *tf)
{
	map_munmap(tf->skel->maps.arraymap, tf->map_elems);
	array_elem_test__destroy(tf->skel);
}

static void test_access_single(void)
{
	struct arr_elem_fixture tf[1];

	setup_fixture(tf, offsetof(struct array_elem_test,
				   progs.access_single));
	run_test(tf);

	ASSERT_EQ(tf->map_elems[0], 1337, "array_elem map value not written");

	destroy_fixture(tf);
}

static void test_access_all(void)
{
	struct arr_elem_fixture tf[1];

	setup_fixture(tf, offsetof(struct array_elem_test,
				   progs.access_all));
	run_test(tf);

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(tf->map_elems[i], i,
			  "array_elem map value not written");

	destroy_fixture(tf);
}

static void test_oob_access(void)
{
	struct arr_elem_fixture tf[1];

	setup_fixture(tf, offsetof(struct array_elem_test,
				   progs.oob_access));
	run_test(tf);

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(tf->map_elems[i], 0,
			  "array_elem map value was written");

	destroy_fixture(tf);
}

static void test_infer_size(void)
{
	struct arr_elem_fixture tf[1];

	setup_fixture(tf, offsetof(struct array_elem_test,
				   progs.infer_size));
	run_test(tf);

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(tf->map_elems[i], i,
			  "array_elem map value not written");

	destroy_fixture(tf);
}

void test_test_array_elem(void)
{
	if (test__start_subtest("real_access_single"))
		test_access_single();
	if (test__start_subtest("real_access_all"))
		test_access_all();
	if (test__start_subtest("real_oob_access"))
		test_oob_access();
	if (test__start_subtest("real_infer_size"))
		test_infer_size();

	/*
	 * RUN_TESTS() will load the *bad* tests, marked with
	 * __failure, and ensure they fail to load.  It will also load the
	 * *good* tests, which we already tested, so you'll see some tests twice
	 * in the output.
	 */
	RUN_TESTS(array_elem_test);
}
