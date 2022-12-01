// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */
#include "testing_helpers.h"
#include "test_progs.h"
#include "test_pinned_devmap.skel.h"

void test_devmap_pinning(void)
{
	struct test_pinned_devmap *ptr;

	ptr = test_pinned_devmap__open_and_load()
	ASSERT_OK_PTR(ptr, "first load");
	test_pinned_devmap__destroy(ptr);
	ASSERT_OK_PTR(test_pinned_devmap__open_and_load(), "re-load");
}

void test_devmap(void)
{
	test_devmap_pinning();
}
