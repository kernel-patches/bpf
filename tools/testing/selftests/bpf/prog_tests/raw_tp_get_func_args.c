// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/bpf.h>
#include "bpf/libbpf_internal.h"
#include "test_raw_tp_get_func_args.skel.h"

static void test_raw_tp_args(bool is_tp_btf)
{
	__u64 args[2] = {0x1234ULL, 0x5678ULL};
	int expected_retval = 0x1234 + 0x5678;
	struct test_raw_tp_get_func_args *skel;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = args,
		.ctx_size_in = sizeof(args),
	);
	int err, prog_fd;

	skel = test_raw_tp_get_func_args__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	bpf_program__set_autoattach(skel->progs.tp_btf_test, is_tp_btf);
	bpf_program__set_autoattach(skel->progs.raw_tp_test, !is_tp_btf);

	err = test_raw_tp_get_func_args__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	if (is_tp_btf)
		prog_fd = bpf_program__fd(skel->progs.tp_btf_test);
	else
		prog_fd = bpf_program__fd(skel->progs.raw_tp_test);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(opts.retval, expected_retval, "check_retval");
	ASSERT_EQ(skel->bss->test_result, 1, "test_result");

cleanup:
	test_raw_tp_get_func_args__destroy(skel);
}

void test_raw_tp_get_func_args(void)
{
	if (test__start_subtest("raw_tp"))
		test_raw_tp_args(false);
	if (test__start_subtest("tp_btf"))
		test_raw_tp_args(true);
}
