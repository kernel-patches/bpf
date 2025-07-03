// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fexit_test.skel.h"
#include "fexit_many_args.skel.h"

static int fexit_test_check(struct fexit_test *fexit_skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd, i;
	__u64 *result;

	prog_fd = bpf_program__fd(fexit_skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	result = (__u64 *)fexit_skel->bss;
	for (i = 0; i < sizeof(*fexit_skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(result[i], 1, "fexit_result"))
			return -1;
	}

	return 0;
}

static int fexit_test_common(struct fexit_test *fexit_skel)
{
	struct bpf_link *link;
	int err;

	err = fexit_test__attach(fexit_skel);
	if (!ASSERT_OK(err, "fexit_attach"))
		return err;

	/* Check that already linked program can't be attached again. */
	link = bpf_program__attach(fexit_skel->progs.test1);
	if (!ASSERT_ERR_PTR(link, "fexit_attach_link"))
		return -1;

	err = fexit_test_check(fexit_skel);
	if (!ASSERT_OK(err, "fexit_test_check"))
		return err;

	fexit_test__detach(fexit_skel);

	/* zero results for re-attach test */
	memset(fexit_skel->bss, 0, sizeof(*fexit_skel->bss));
	return 0;
}

static void fexit_test(void)
{
	struct fexit_test *fexit_skel = NULL;
	int err;

	fexit_skel = fexit_test__open_and_load();
	if (!ASSERT_OK_PTR(fexit_skel, "fexit_skel_load"))
		goto cleanup;

	err = fexit_test_common(fexit_skel);
	if (!ASSERT_OK(err, "fexit_first_attach"))
		goto cleanup;

	err = fexit_test_common(fexit_skel);
	ASSERT_OK(err, "fexit_second_attach");

cleanup:
	fexit_test__destroy(fexit_skel);
}

static void fexit_many_args(void)
{
	struct fexit_many_args *fexit_skel = NULL;
	int err;

	fexit_skel = fexit_many_args__open_and_load();
	if (!ASSERT_OK_PTR(fexit_skel, "fexit_many_args_skel_load"))
		goto cleanup;

	err = fexit_many_args__attach(fexit_skel);
	if (!ASSERT_OK(err, "fexit_many_args_attach"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(1), "trigger_read");

	ASSERT_EQ(fexit_skel->bss->test1_result, 1,
		  "fexit_many_args_result1");
	ASSERT_EQ(fexit_skel->bss->test2_result, 1,
		  "fexit_many_args_result2");
	ASSERT_EQ(fexit_skel->bss->test3_result, 1,
		  "fexit_many_args_result3");

cleanup:
	fexit_many_args__destroy(fexit_skel);
}

static void fexit_test_multi(void)
{
	struct fexit_test *fexit_skel = NULL;
	int err, prog_cnt;

	fexit_skel = fexit_test__open();
	if (!ASSERT_OK_PTR(fexit_skel, "fexit_skel_open"))
		goto cleanup;

	prog_cnt = sizeof(fexit_skel->progs) / sizeof(long);
	err = bpf_to_tracing_multi((void *)&fexit_skel->progs, prog_cnt);
	if (!ASSERT_OK(err, "fexit_to_multi"))
		goto cleanup;

	err = fexit_test__load(fexit_skel);
	if (!ASSERT_OK(err, "fexit_skel_load"))
		goto cleanup;

	err = bpf_attach_as_tracing_multi((void *)&fexit_skel->progs,
					  prog_cnt,
					  (void *)&fexit_skel->links);
	if (!ASSERT_OK(err, "fexit_attach_multi"))
		goto cleanup;

	err = fexit_test_check(fexit_skel);
	ASSERT_OK(err, "fexit_first_attach");
cleanup:
	fexit_test__destroy(fexit_skel);
}

void test_fexit_test(void)
{
	if (test__start_subtest("fexit"))
		fexit_test();
	if (test__start_subtest("fexit_multi"))
		fexit_test_multi();
	if (test__start_subtest("fexit_many_args"))
		fexit_many_args();
}
