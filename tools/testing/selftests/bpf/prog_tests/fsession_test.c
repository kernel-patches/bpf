// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <test_progs.h>
#include "fsession_test.skel.h"
#include "fsession_cookie.skel.h"
#include "fsession_mixed.skel.h"

static int check_result(struct fsession_test *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	/* Trigger test function calls */
	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		return err;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		return topts.retval;

	for (int i = 0; i < sizeof(*skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(((__u64 *)skel->bss)[i], 1, "test_result"))
			return -EINVAL;
	}

	/* some fields go to the "data" sections, not "bss" */
	for (int i = 0; i < sizeof(*skel->data) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(((__u64 *)skel->data)[i], 1, "test_result"))
			return -EINVAL;
	}
	return 0;
}

static void test_fsession_basic(void)
{
	struct fsession_test *skel = NULL;
	int err;

	skel = fsession_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open_and_load"))
		goto cleanup;

	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_attach"))
		goto cleanup;

	check_result(skel);
cleanup:
	fsession_test__destroy(skel);
}

static void test_fsession_reattach(void)
{
	struct fsession_test *skel = NULL;
	int err;

	skel = fsession_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open_and_load"))
		goto cleanup;

	/* First attach */
	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_first_attach"))
		goto cleanup;

	if (check_result(skel))
		goto cleanup;

	/* Detach */
	fsession_test__detach(skel);

	/* Reset counters */
	memset(skel->bss, 0, sizeof(*skel->bss));

	/* Second attach */
	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_second_attach"))
		goto cleanup;

	if (check_result(skel))
		goto cleanup;

cleanup:
	fsession_test__destroy(skel);
}

static void test_fsession_cookie(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct fsession_cookie *skel = NULL;
	int err, prog_fd;

	skel = fsession_cookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fsession_cookie__open_and_load"))
		goto cleanup;

	err = fsession_cookie__attach(skel);
	if (!ASSERT_OK(err, "fsession_cookie_attach"))
		goto cleanup;

	/* Trigger target once */
	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		goto cleanup;

	for (int i = 0; i < sizeof(*skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(((__u64 *)skel->bss)[i], 1, "test_result"))
			goto cleanup;
	}

cleanup:
	fsession_cookie__destroy(skel);
}

static void test_fsession_mixed(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct fsession_mixed *skel = NULL;
	int err, prog_fd;

	skel = fsession_mixed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fsession_mixed__open_and_load"))
		goto cleanup;

	err = fsession_mixed__attach(skel);
	if (!ASSERT_OK(err, "fsession_mixed_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		goto cleanup;

	for (int i = 0; i < sizeof(*skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(((__u64 *)skel->bss)[i], 1, "test_result"))
			goto cleanup;
	}
cleanup:
	fsession_mixed__destroy(skel);
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
	if (test__start_subtest("fsession_cookie"))
		test_fsession_cookie();
	if (test__start_subtest("fsession_mixed"))
		test_fsession_mixed();
}
