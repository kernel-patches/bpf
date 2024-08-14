// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test_kfunc_in_tp.skel.h"
#include "test_progs.h"

static void run_tp(void)
{
	(void)syscall(__NR_getpid);
}

void test_kfunc_in_tp(void)
{
	struct test_kfunc_in_tp *skel;
	int err;

	skel = test_kfunc_in_tp__open();
	ASSERT_OK_PTR(skel, "test_kfunc_in_tp__open");

	err = test_kfunc_in_tp__load(skel);
	ASSERT_OK(err, "test_kfunc_in_tp__load");

	err = test_kfunc_in_tp__attach(skel);
	ASSERT_OK(err, "test_kfunc_in_tp__attach");

	run_tp();
	ASSERT_OK(skel->data->result, "complete");

	test_kfunc_in_tp__destroy(skel);
}
