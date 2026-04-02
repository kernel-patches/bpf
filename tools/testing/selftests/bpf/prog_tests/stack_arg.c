// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>
#include "stack_arg.skel.h"
#include "stack_arg_kfunc.skel.h"

static void test_nesting(void)
{
	struct stack_arg *skel;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	skel = stack_arg__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (!skel->rodata->has_stack_arg) {
		test__skip();
		goto out;
	}

	err = stack_arg__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	skel->bss->a = 0;
	skel->bss->b = 0;
	skel->bss->c = 0;
	skel->bss->d = 0;
	skel->bss->e = 0;
	skel->bss->f = 6;
	skel->bss->g = 7;
	skel->bss->i = 8;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 29, "retval");

out:
	stack_arg__destroy(skel);
}

static void run_subtest(struct bpf_program *prog, int expected)
{
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	prog_fd = bpf_program__fd(prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, expected, "retval");
}

static void test_global_many(void)
{
	struct stack_arg *skel;

	skel = stack_arg__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (!skel->rodata->has_stack_arg) {
		test__skip();
		goto out;
	}

	if (!ASSERT_OK(stack_arg__load(skel), "load"))
		goto out;

	run_subtest(skel->progs.test_global_many_args, 36);

out:
	stack_arg__destroy(skel);
}

static void test_async_cb_many(void)
{
	struct stack_arg *skel;

	skel = stack_arg__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (!skel->rodata->has_stack_arg) {
		test__skip();
		goto out;
	}

	if (!ASSERT_OK(stack_arg__load(skel), "load"))
		goto out;

	run_subtest(skel->progs.test_async_cb_many_args, 0);

out:
	stack_arg__destroy(skel);
}

static void test_kfunc(void)
{
	struct stack_arg_kfunc *skel;

	skel = stack_arg_kfunc__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (!skel->rodata->has_stack_arg) {
		test__skip();
		goto out;
	}

	if (!ASSERT_OK(stack_arg_kfunc__load(skel), "load"))
		goto out;

	run_subtest(skel->progs.test_stack_arg_scalar, 36);
	run_subtest(skel->progs.test_stack_arg_ptr, 45);
	run_subtest(skel->progs.test_stack_arg_mix, 51);

out:
	stack_arg_kfunc__destroy(skel);
}

void test_stack_arg(void)
{
	if (test__start_subtest("nesting"))
		test_nesting();
	if (test__start_subtest("global_many_args"))
		test_global_many();
	if (test__start_subtest("async_cb_many_args"))
		test_async_cb_many();
	if (test__start_subtest("kfunc"))
		test_kfunc();
}
