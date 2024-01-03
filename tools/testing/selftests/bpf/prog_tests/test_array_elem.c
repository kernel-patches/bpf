// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */
#include <test_progs.h>
#include "array_elem_test.skel.h"

#define NR_MAP_ELEMS 100

/*
 * Helper to load and run a program.
 * Call must define skel, map_elems, and bss_elems.
 * Destroy the skel when you're done.
 */
#define load_and_run(PROG) ({						\
	int err;							\
	skel = array_elem_test__open();					\
	if (!ASSERT_OK_PTR(skel, "array_elem_test open"))		\
		return;							\
	bpf_program__set_autoload(skel->progs.x_ ## PROG, true);	\
	err = array_elem_test__load(skel);				\
	if (!ASSERT_EQ(err, 0, "array_elem_test load")) {		\
		array_elem_test__destroy(skel);				\
		return;							\
	}								\
	err = array_elem_test__attach(skel);				\
	if (!ASSERT_EQ(err, 0, "array_elem_test attach")) {		\
		array_elem_test__destroy(skel);				\
		return;							\
	}								\
	for (int i = 0; i < NR_MAP_ELEMS; i++)				\
		skel->bss->lookup_indexes[i] = i;			\
	map_elems = bpf_map__mmap(skel->maps.arraymap);			\
	ASSERT_OK_PTR(map_elems, "mmap");				\
	bss_elems = skel->bss->bss_elems;				\
	skel->bss->target_pid = getpid();				\
	usleep(1);							\
})

static void test_access_all(void)
{
	struct array_elem_test *skel;
	int *map_elems;
	int *bss_elems;

	load_and_run(access_all);

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(map_elems[i], i, "array_elem map value not written");

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(bss_elems[i], i, "array_elem bss value not written");

	array_elem_test__destroy(skel);
}

static void test_oob_access(void)
{
	struct array_elem_test *skel;
	int *map_elems;
	int *bss_elems;

	load_and_run(oob_access);

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(map_elems[i], 0, "array_elem map value was written");

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(bss_elems[i], 0, "array_elem bss value was written");

	array_elem_test__destroy(skel);
}

static void test_access_array_map_infer_sz(void)
{
	struct array_elem_test *skel;
	int *map_elems;
	int *bss_elems __maybe_unused;

	load_and_run(access_array_map_infer_sz);

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		ASSERT_EQ(map_elems[i], i, "array_elem map value not written");

	array_elem_test__destroy(skel);
}


/* Test that attempting to load a bad program fails. */
#define test_bad(PROG) ({						\
	struct array_elem_test *skel;					\
	int err;							\
	skel = array_elem_test__open();					\
	if (!ASSERT_OK_PTR(skel, "array_elem_test open"))		\
		return;							\
	bpf_program__set_autoload(skel->progs.x_bad_ ## PROG, true); 	\
	err = array_elem_test__load(skel);				\
	ASSERT_ERR(err, "array_elem_test load " # PROG);		\
	array_elem_test__destroy(skel);					\
})

void test_test_array_elem(void)
{
	if (test__start_subtest("array_elem_access_all"))
		test_access_all();
	if (test__start_subtest("array_elem_oob_access"))
		test_oob_access();
	if (test__start_subtest("array_elem_access_array_map_infer_sz"))
		test_access_array_map_infer_sz();
	if (test__start_subtest("array_elem_bad_map_array_access"))
		test_bad(map_array_access);
	if (test__start_subtest("array_elem_bad_bss_array_access"))
		test_bad(bss_array_access);
}
