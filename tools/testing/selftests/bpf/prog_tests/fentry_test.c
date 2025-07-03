// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fentry_test.skel.h"
#include "fentry_many_args.skel.h"

static int fentry_test_check(struct fentry_test *fentry_skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd, i;
	__u64 *result;

	prog_fd = bpf_program__fd(fentry_skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	result = (__u64 *)fentry_skel->bss;
	for (i = 0; i < sizeof(*fentry_skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(result[i], 1, "fentry_result"))
			return -1;
	}

	return 0;
}

static int fentry_test_common(struct fentry_test *fentry_skel)
{
	struct bpf_link *link;
	int err;

	err = fentry_test__attach(fentry_skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		return err;

	/* Check that already linked program can't be attached again. */
	link = bpf_program__attach(fentry_skel->progs.test1);
	if (!ASSERT_ERR_PTR(link, "fentry_attach_link"))
		return -1;

	err = fentry_test_check(fentry_skel);
	if (!ASSERT_OK(err, "fentry_test_check"))
		return err;

	fentry_test__detach(fentry_skel);

	/* zero results for re-attach test */
	memset(fentry_skel->bss, 0, sizeof(*fentry_skel->bss));
	return 0;
}

static void fentry_test(void)
{
	struct fentry_test *fentry_skel = NULL;
	int err;

	fentry_skel = fentry_test__open_and_load();
	if (!ASSERT_OK_PTR(fentry_skel, "fentry_skel_load"))
		goto cleanup;

	err = fentry_test_common(fentry_skel);
	if (!ASSERT_OK(err, "fentry_first_attach"))
		goto cleanup;

	err = fentry_test_common(fentry_skel);
	ASSERT_OK(err, "fentry_second_attach");

cleanup:
	fentry_test__destroy(fentry_skel);
}

static void fentry_many_args(void)
{
	struct fentry_many_args *fentry_skel = NULL;
	int err;

	fentry_skel = fentry_many_args__open_and_load();
	if (!ASSERT_OK_PTR(fentry_skel, "fentry_many_args_skel_load"))
		goto cleanup;

	err = fentry_many_args__attach(fentry_skel);
	if (!ASSERT_OK(err, "fentry_many_args_attach"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(1), "trigger_read");

	ASSERT_EQ(fentry_skel->bss->test1_result, 1,
		  "fentry_many_args_result1");
	ASSERT_EQ(fentry_skel->bss->test2_result, 1,
		  "fentry_many_args_result2");
	ASSERT_EQ(fentry_skel->bss->test3_result, 1,
		  "fentry_many_args_result3");

cleanup:
	fentry_many_args__destroy(fentry_skel);
}

static void fentry_multi_test(void)
{
	struct fentry_test *fentry_skel = NULL;
	int err, prog_cnt;

	fentry_skel = fentry_test__open();
	if (!ASSERT_OK_PTR(fentry_skel, "fentry_skel_open"))
		goto cleanup;

	prog_cnt = sizeof(fentry_skel->progs) / sizeof(long);
	err = bpf_to_tracing_multi((void *)&fentry_skel->progs, prog_cnt);
	if (!ASSERT_OK(err, "fentry_to_multi"))
		goto cleanup;

	err = fentry_test__load(fentry_skel);
	if (!ASSERT_OK(err, "fentry_skel_load"))
		goto cleanup;

	err = bpf_attach_as_tracing_multi((void *)&fentry_skel->progs,
					  prog_cnt,
					  (void *)&fentry_skel->links);
	if (!ASSERT_OK(err, "fentry_attach_multi"))
		goto cleanup;

	err = fentry_test_check(fentry_skel);
	ASSERT_OK(err, "fentry_first_attach");
cleanup:
	fentry_test__destroy(fentry_skel);
}

void test_fentry_test(void)
{
	if (test__start_subtest("fentry"))
		fentry_test();
	if (test__start_subtest("fentry_multi"))
		fentry_multi_test();
	if (test__start_subtest("fentry_many_args"))
		fentry_many_args();
}
