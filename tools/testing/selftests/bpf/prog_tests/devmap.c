// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Google
#include "testing_helpers.h"
#include "test_progs.h"
#include "test_pinned_devmap.skel.h"
#include "test_pinned_devmap_rdonly_prog.skel.h"

void test_devmap_pinning(void)
{
	struct test_pinned_devmap *ptr;

	ASSERT_OK_PTR(ptr = test_pinned_devmap__open_and_load(), "first load");
	test_pinned_devmap__destroy(ptr);
	ASSERT_OK_PTR(test_pinned_devmap__open_and_load(), "re-load");
}

void test_devmap(void)
{
	if (test__start_subtest("pinned_devmap"))
		test_devmap_pinning();
}
