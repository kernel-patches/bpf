/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */

#include <test_progs.h>
#include <sys/un.h>
#include "test_prog_array_init.skel.h"

void test_prog_array_init(void)
{
	struct test_prog_array_init *skel;
	int err;

	skel = test_prog_array_init__open();
	if (!ASSERT_OK_PTR(skel, "could not open BPF object"))
		return;

	err = test_prog_array_init__load(skel);
	if (!ASSERT_OK(err, "could not load BPF object"))
		goto cleanup;

	err = test_prog_array_init__attach(skel);
	if (!ASSERT_OK(err, "could not attach BPF object"))
		goto cleanup;

cleanup:
	test_prog_array_init__destroy(skel);
}
