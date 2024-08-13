// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "struct_ops_syscall.skel.h"

#define KFUNC_A100    100
#define KFUNC_A10      10
#define SUBPROG_A       1
#define EPILOGUE_A (10000 + KFUNC_A100 + KFUNC_A10)
#define PROLOGUE_A  (1000 + KFUNC_A100 + KFUNC_A10)

#define SUBPROG_TEST_MAIN	SUBPROG_A
#define KFUNC_TEST_MAIN		(KFUNC_A10 + SUBPROG_A)

struct st_ops_args {
	int a;
};

static void do_test(struct struct_ops_syscall *skel,
		    struct bpf_map *st_ops_map, int main_prog_a)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd, expected_a;
	struct st_ops_args args;
	struct bpf_link *link;

	topts.ctx_in = &args;
	topts.ctx_size_in = sizeof(args);

	link = bpf_map__attach_struct_ops(st_ops_map);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		return;

	/* gen_prologue + main prog */
	expected_a = PROLOGUE_A + main_prog_a;
	memset(&args, 0, sizeof(args));
	prog_fd = bpf_program__fd(skel->progs.syscall_prologue);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(args.a, expected_a, "args.a");
	ASSERT_EQ(topts.retval, 0, "topts.retval");

	/* main prog + gen_epilogue */
	expected_a =  main_prog_a + EPILOGUE_A;
	memset(&args, 0, sizeof(args));
	prog_fd = bpf_program__fd(skel->progs.syscall_epilogue);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(args.a, expected_a, "args.a");
	ASSERT_EQ(topts.retval, expected_a * 2, "topts.retval");

	/* gen_prologue + main prog + gen_epilogue */
	expected_a = PROLOGUE_A + main_prog_a + EPILOGUE_A;
	memset(&args, 0, sizeof(args));
	prog_fd = bpf_program__fd(skel->progs.syscall_pro_epilogue);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(args.a, expected_a, "args.a");
	ASSERT_EQ(topts.retval, expected_a * 2, "topts.retval");
	bpf_link__destroy(link);
}

void test_struct_ops_syscall(void)
{
	struct struct_ops_syscall *skel;

	skel = struct_ops_syscall__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	if (test__start_subtest("subprog"))
		do_test(skel, skel->maps.pro_epilogue_subprog_ops,
			SUBPROG_TEST_MAIN);

	if (test__start_subtest("kfunc"))
		do_test(skel, skel->maps.pro_epilogue_kfunc_ops,
			KFUNC_TEST_MAIN);

	if (test__start_subtest("tailcall")) {
		const int zero = 0;
		int prog_fd = bpf_program__fd(skel->progs.test_epilogue_subprog);
		int map_fd = bpf_map__fd(skel->maps.epilogue_map);
		int err;

		err = bpf_map_update_elem(map_fd, &zero, &prog_fd, 0);
		if (ASSERT_OK(err, "map_update(epilogue_map)"))
			do_test(skel, skel->maps.pro_epilogue_tail_ops,
				SUBPROG_TEST_MAIN);
	}

	struct_ops_syscall__destroy(skel);
}
