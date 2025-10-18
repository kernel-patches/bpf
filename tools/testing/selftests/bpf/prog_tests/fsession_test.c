// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <test_progs.h>
#include "fsession_test.skel.h"

static void test_fsession_basic(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct fsession_test *skel = NULL;
	int err, prog_fd;

	skel = fsession_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open_and_load"))
		goto cleanup;

	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_attach"))
		goto cleanup;

	/* Trigger test function calls */
	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		return;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		return;

	/* Verify test1: both entry and exit are called */
	ASSERT_EQ(skel->bss->test1_entry_called, 1, "test1_entry_called");
	ASSERT_EQ(skel->bss->test1_exit_called, 1, "test1_exit_called");
	ASSERT_EQ(skel->bss->test1_entry_result, 1, "test1_entry_result");
	ASSERT_EQ(skel->bss->test1_exit_result, 1, "test1_exit_result");

	/* Verify test2: entry is called but exit is blocked */
	ASSERT_EQ(skel->bss->test2_entry_called, 1, "test2_entry_called");
	ASSERT_EQ(skel->bss->test2_exit_called, 0, "test2_exit_not_called");
	ASSERT_EQ(skel->bss->test2_entry_result, 1, "test2_entry_result");
	ASSERT_EQ(skel->bss->test2_exit_result, 0, "test2_exit_result");

	/* Verify test3: both entry and exit are called */
	ASSERT_EQ(skel->bss->test3_entry_called, 1, "test3_entry_called");
	ASSERT_EQ(skel->bss->test3_exit_called, 1, "test3_exit_called");
	ASSERT_EQ(skel->bss->test3_entry_result, 1, "test3_entry_result");
	ASSERT_EQ(skel->bss->test3_exit_result, 1, "test3_exit_result");

	/* Verify test4: both entry and exit are called */
	ASSERT_EQ(skel->bss->test4_entry_called, 1, "test4_entry_called");
	ASSERT_EQ(skel->bss->test4_exit_called, 1, "test4_exit_called");
	ASSERT_EQ(skel->bss->test4_entry_result, 1, "test4_entry_result");
	ASSERT_EQ(skel->bss->test4_exit_result, 1, "test4_exit_result");

	/* Verify test5: both entry and exit are called */
	ASSERT_EQ(skel->bss->test5_entry_called, 1, "test5_entry_called");
	ASSERT_EQ(skel->bss->test5_exit_called, 1, "test5_exit_called");
	ASSERT_EQ(skel->bss->test5_entry_result, 1, "test5_entry_result");
	ASSERT_EQ(skel->bss->test5_exit_result, 1, "test5_exit_result");

	/* Verify test6: entry is called but exit is blocked */
	ASSERT_EQ(skel->bss->test6_entry_called, 1, "test6_entry_called");
	ASSERT_EQ(skel->bss->test6_exit_called, 0, "test6_exit_not_called");
	ASSERT_EQ(skel->bss->test6_entry_result, 1, "test6_entry_result");
	ASSERT_EQ(skel->bss->test6_exit_result, 0, "test6_exit_result");

	/* Verify test7: entry is called but exit is blocked */
	ASSERT_EQ(skel->bss->test7_entry_called, 1, "test7_entry_called");
	ASSERT_EQ(skel->bss->test7_exit_called, 0, "test7_exit_not_called");
	ASSERT_EQ(skel->bss->test7_entry_result, 1, "test7_entry_result");
	ASSERT_EQ(skel->bss->test7_exit_result, 0, "test7_exit_result");

cleanup:
	fsession_test__destroy(skel);
}

static void test_fsession_reattach(void)
{
	struct fsession_test *skel = NULL;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = fsession_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open_and_load"))
		goto cleanup;

	/* First attach */
	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_first_attach"))
		goto cleanup;

	/* Trigger test function calls */
	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		return;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		return;

	/* Verify first call */
	ASSERT_EQ(skel->bss->test1_entry_called, 1, "test1_entry_first");
	ASSERT_EQ(skel->bss->test1_exit_called, 1, "test1_exit_first");

	/* Detach */
	fsession_test__detach(skel);

	/* Reset counters */
	memset(skel->bss, 0, sizeof(*skel->bss));

	/* Second attach */
	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_second_attach"))
		goto cleanup;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		return;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		return;

	/* Verify second call */
	ASSERT_EQ(skel->bss->test1_entry_called, 1, "test1_entry_second");
	ASSERT_EQ(skel->bss->test1_exit_called, 1, "test1_exit_second");

cleanup:
	fsession_test__destroy(skel);
}

void test_fsession_test(void)
{
#if !defined(__x86_64__)
	test__skip();
	return;
#endif
	if (test__start_subtest("fsession_basic"))
		test_fsession_basic();
	if (test__start_subtest("fsession_reattach"))
		test_fsession_reattach();
}
