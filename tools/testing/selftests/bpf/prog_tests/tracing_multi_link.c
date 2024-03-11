// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Bytedance. */

#include <test_progs.h>
#include "tracing_multi_test.skel.h"

static void test_skel_auto_api(void)
{
	struct tracing_multi_test *skel;
	int err;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	/* disable all programs that should fail */
	bpf_program__set_autoattach(skel->progs.fentry_fail_test1, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test2, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test3, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test4, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test5, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test6, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test7, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test8, false);

	bpf_program__set_autoattach(skel->progs.fexit_fail_test1, false);
	bpf_program__set_autoattach(skel->progs.fexit_fail_test2, false);
	bpf_program__set_autoattach(skel->progs.fexit_fail_test3, false);

	err = tracing_multi_test__attach(skel);
	bpf_object__free_btfs(skel->obj);
	if (!ASSERT_OK(err, "tracing_multi_test__attach"))
		goto cleanup;

cleanup:
	tracing_multi_test__destroy(skel);
}

static void test_skel_manual_api(void)
{
	struct tracing_multi_test *skel;
	struct bpf_link *link;
	int err;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

#define RUN_TEST(name, success)						\
do {									\
	link = bpf_program__attach(skel->progs.name);			\
	err = libbpf_get_error(link);					\
	if (!ASSERT_OK(success ? err : !err,				\
		       "bpf_program__attach: " #name))			\
		goto cleanup;						\
	skel->links.name = err ? NULL : link;				\
} while (0)

	RUN_TEST(fentry_success_test1, true);
	RUN_TEST(fentry_success_test2, true);
	RUN_TEST(fentry_success_test3, true);
	RUN_TEST(fentry_success_test4, true);
	RUN_TEST(fentry_success_test5, true);

	RUN_TEST(fexit_success_test1, true);
	RUN_TEST(fexit_success_test2, true);

	RUN_TEST(fmod_ret_success_test1, true);

	RUN_TEST(fentry_fail_test1, false);
	RUN_TEST(fentry_fail_test2, false);
	RUN_TEST(fentry_fail_test3, false);
	RUN_TEST(fentry_fail_test4, false);
	RUN_TEST(fentry_fail_test5, false);
	RUN_TEST(fentry_fail_test6, false);
	RUN_TEST(fentry_fail_test7, false);
	RUN_TEST(fentry_fail_test8, false);

	RUN_TEST(fexit_fail_test1, false);
	RUN_TEST(fexit_fail_test2, false);
	RUN_TEST(fexit_fail_test3, false);

cleanup:
	tracing_multi_test__destroy(skel);
}

static void tracing_multi_test_run(struct tracing_multi_test *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	prog_fd = bpf_program__fd(skel->progs.fentry_manual_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->fentry_test1_result, 1, "fentry_test1_result");
	ASSERT_EQ(skel->bss->fentry_test2_result, 1, "fentry_test2_result");
	ASSERT_EQ(skel->bss->fentry_test3_result, 1, "fentry_test3_result");
	ASSERT_EQ(skel->bss->fentry_test4_result, 1, "fentry_test4_result");
	ASSERT_EQ(skel->bss->fentry_test5_result, 1, "fentry_test5_result");
	ASSERT_EQ(skel->bss->fentry_test6_result, 1, "fentry_test6_result");
	ASSERT_EQ(skel->bss->fentry_test7_result, 1, "fentry_test7_result");
	ASSERT_EQ(skel->bss->fentry_test8_result, 1, "fentry_test8_result");
}

static void test_attach_api(void)
{
	LIBBPF_OPTS(bpf_trace_multi_opts, opts);
	struct tracing_multi_test *skel;
	struct bpf_link *link;
	const char *syms[8] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
		"bpf_fentry_test3",
		"bpf_fentry_test4",
		"bpf_fentry_test5",
		"bpf_fentry_test6",
		"bpf_fentry_test7",
		"bpf_fentry_test8",
	};
	__u64 cookies[] = {1, 7, 2, 3, 4, 5, 6, 8};

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	opts.syms = syms;
	opts.cookies = cookies;
	opts.cnt = ARRAY_SIZE(syms);
	link = bpf_program__attach_trace_multi_opts(skel->progs.fentry_manual_test1,
						    &opts);
	bpf_object__free_btfs(skel->obj);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace_multi_opts"))
		goto cleanup;
	skel->links.fentry_manual_test1 = link;

	skel->bss->pid = getpid();
	skel->bss->test_cookie = true;
	tracing_multi_test_run(skel);
cleanup:
	tracing_multi_test__destroy(skel);
}

void test_tracing_multi_attach(void)
{
	if (test__start_subtest("skel_auto_api"))
		test_skel_auto_api();
	if (test__start_subtest("skel_manual_api"))
		test_skel_manual_api();
	if (test__start_subtest("attach_api"))
		test_attach_api();
}
