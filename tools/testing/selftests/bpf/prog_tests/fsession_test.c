// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <test_progs.h>
#include "fsession_test.skel.h"

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

	return 0;
}

static void test_fsession_basic(void)
{
	struct fsession_test *skel = NULL;
	int err;

	skel = fsession_test__open();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open"))
		return;

	err = fsession_test__load(skel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "fsession_test__load"))
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

	skel = fsession_test__open();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open"))
		return;

	err = fsession_test__load(skel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "fsession_test__load"))
		goto cleanup;

	/* first attach */
	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_first_attach"))
		goto cleanup;

	if (check_result(skel))
		goto cleanup;

	/* detach */
	fsession_test__detach(skel);

	/* reset counters */
	memset(skel->bss, 0, sizeof(*skel->bss));

	/* second attach */
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
	struct fsession_test *skel = NULL;
	int err;

	skel = fsession_test__open();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open"))
		goto cleanup;

	/*
	 * The test_fsession_basic() will test the session cookie with
	 * bpf_get_func_ip() case, so we need only check
	 * the cookie without bpf_get_func_ip() case here
	 */
	bpf_program__set_autoload(skel->progs.test6, false);

	err = fsession_test__load(skel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "fsession_test__load"))
		goto cleanup;

	err = fsession_test__attach(skel);
	if (!ASSERT_OK(err, "fsession_attach"))
		goto cleanup;

	skel->bss->test6_entry_result = 1;
	skel->bss->test6_exit_result = 1;

	check_result(skel);
cleanup:
	fsession_test__destroy(skel);
}

static void test_fsession_prog_array_session_kfunc_compat(void)
{
	struct fsession_test *skel = NULL;
	__u32 key = 0, session_kfunc_prog_fd, no_session_kfunc_prog_fd;
	int map_fd = -1, err;

	skel = fsession_test__open();
	if (!ASSERT_OK_PTR(skel, "fsession_test__open"))
		goto cleanup;

	err = fsession_test__load(skel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "fsession_test__load"))
		goto cleanup;

	session_kfunc_prog_fd = bpf_program__fd(skel->progs.test9);
	no_session_kfunc_prog_fd = bpf_program__fd(skel->progs.test12);
	if (!ASSERT_GE(session_kfunc_prog_fd, 0, "session_kfunc_prog_fd"))
		goto cleanup;
	if (!ASSERT_GE(no_session_kfunc_prog_fd, 0, "no_session_kfunc_prog_fd"))
		goto cleanup;

	map_fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, NULL, sizeof(key),
				sizeof(__u32), 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "bpf_map_create"))
		goto cleanup;

	err = bpf_map_update_elem(map_fd, &key, &no_session_kfunc_prog_fd, BPF_ANY);
	if (!ASSERT_OK(err, "bpf_map_update_elem success"))
		goto cleanup;

	err = bpf_map_update_elem(map_fd, &key, &session_kfunc_prog_fd, BPF_ANY);
	if (!ASSERT_ERR(err, "bpf_map_update_elem failure"))
		goto cleanup;
	ASSERT_EQ(errno, EINVAL, "bpf_map_update_elem errno");

cleanup:
	if (map_fd >= 0)
		close(map_fd);
	fsession_test__destroy(skel);
}

void test_fsession_test(void)
{
	if (test__start_subtest("fsession_test"))
		test_fsession_basic();
	if (test__start_subtest("fsession_reattach"))
		test_fsession_reattach();
	if (test__start_subtest("fsession_cookie"))
		test_fsession_cookie();
	if (test__start_subtest("fsession_prog_array_session_kfunc_compat"))
		test_fsession_prog_array_session_kfunc_compat();
}
