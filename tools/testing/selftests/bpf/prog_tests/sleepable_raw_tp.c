// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <time.h>
#include "test_sleepable_raw_tp.skel.h"
#include "test_sleepable_raw_tp_fail.skel.h"

static void test_sleepable_raw_tp_success(void)
{
	struct test_sleepable_raw_tp *skel;
	int err;

	skel = test_sleepable_raw_tp__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		return;

	skel->bss->target_pid = getpid();

	err = test_sleepable_raw_tp__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	syscall(__NR_nanosleep, &(struct timespec){ .tv_nsec = 555 }, NULL);

	ASSERT_EQ(skel->bss->triggered, 1, "triggered");
	ASSERT_EQ(skel->bss->err, 0, "err");
	ASSERT_EQ(skel->bss->copied_tv_nsec, 555, "copied_tv_nsec");

cleanup:
	test_sleepable_raw_tp__destroy(skel);
}

static void test_sleepable_raw_tp_reject(void)
{
	struct test_sleepable_raw_tp_fail *skel;
	int err;

	skel = test_sleepable_raw_tp_fail__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		goto cleanup;

	err = test_sleepable_raw_tp_fail__attach(skel);
	ASSERT_ERR(err, "skel_attach_should_fail");

cleanup:
	test_sleepable_raw_tp_fail__destroy(skel);
}

void test_sleepable_raw_tp(void)
{
	if (test__start_subtest("success"))
		test_sleepable_raw_tp_success();
	if (test__start_subtest("reject_non_faultable"))
		test_sleepable_raw_tp_reject();
}
