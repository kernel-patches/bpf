// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <network_helpers.h>
#include "aggregate_ret_int128_c.skel.h"
#include "aggregate_ret_struct_c.skel.h"
#include "aggregate_ret_union_c.skel.h"
#include "aggregate_ret_run.skel.h"
#include "aggregate_ret_func.skel.h"
#include "aggregate_ret_kfunc.skel.h"

/*
 * Run one program and check its result. The program returns 0 on success, or
 * 1..4 identifying which half of which aggregate (R0:R2) return value came back
 * wrong. A return of -1 means the program was built with an LLVM that lacks
 * R0:R2 16-byte return support, in which case the subtest is skipped.
 */
static void run_prog(struct bpf_program *prog, bool may_skip)
{
	char buf[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = buf,
		.data_size_in = sizeof(buf),
		.repeat = 1,
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	if (!ASSERT_OK(err, "test_run"))
		return;

	if (may_skip && (int)topts.retval == -1) {
		test__skip();
		return;
	}

	ASSERT_EQ(topts.retval, 0, "aggregate_ret_result");
}

void test_aggregate_ret(void)
{
	struct aggregate_ret_struct_c *skel_struct_c;
	struct aggregate_ret_union_c *skel_union_c;
	struct aggregate_ret_int128_c *skel_c;
	struct aggregate_ret_run *skel_run;

	skel_c = aggregate_ret_int128_c__open_and_load();
	if (!ASSERT_OK_PTR(skel_c, "skel_c_open_load"))
		return;

	/* C variant (__int128): relies on LLVM 23 R0:R2 codegen, skipped otherwise. */
	if (test__start_subtest("int128_c"))
		run_prog(skel_c->progs.aggregate_ret_test, true);

	aggregate_ret_int128_c__destroy(skel_c);

	skel_struct_c = aggregate_ret_struct_c__open_and_load();
	if (!ASSERT_OK_PTR(skel_struct_c, "skel_struct_c_open_load"))
		return;

	/*
	 * C variant returning a 16-byte struct by value: exercises the struct
	 * branch of bpf_ret_reg_pair(). Also LLVM 23 only.
	 */
	if (test__start_subtest("struct_c"))
		run_prog(skel_struct_c->progs.aggregate_ret_struct_c_test, true);

	/*
	 * Same 16-byte struct return, but from a global (non-static) callee:
	 * exercises the compiler lowering a global struct-returning function to
	 * R0:R2 and the verifier's global return path end to end. Also LLVM 23
	 * only.
	 */
	if (test__start_subtest("global_struct_c"))
		run_prog(skel_struct_c->progs.aggregate_ret_global_struct_c_test, true);

	/*
	 * Same 16-byte struct, but returned by value from a kfunc: exercises
	 * the struct branch of check_kfunc_call() and the JIT RDX->R2 move.
	 * Also LLVM 23 only.
	 */
	if (test__start_subtest("kfunc_struct_c"))
		run_prog(skel_struct_c->progs.aggregate_ret_kfunc_struct_c_test, true);

	aggregate_ret_struct_c__destroy(skel_struct_c);

	skel_union_c = aggregate_ret_union_c__open_and_load();
	if (!ASSERT_OK_PTR(skel_union_c, "skel_union_c_open_load"))
		return;

	/*
	 * C variant returning a 16-byte union by value: exercises the union BTF
	 * kind through the same struct branch of bpf_ret_reg_pair().
	 * Also LLVM 23 only.
	 */
	if (test__start_subtest("union_c"))
		run_prog(skel_union_c->progs.aggregate_ret_union_c_test, true);

	aggregate_ret_union_c__destroy(skel_union_c);

	skel_run = aggregate_ret_run__open_and_load();
	if (!ASSERT_OK_PTR(skel_run, "skel_run_open_load"))
		return;

	/* Inline-asm variant: compiler-version independent, always runs. */
	if (test__start_subtest("asm"))
		run_prog(skel_run->progs.aggregate_ret_asm_test, false);

	/* Struct-by-value kfunc returns, also compiler-version independent. */
	if (test__start_subtest("struct"))
		run_prog(skel_run->progs.aggregate_ret_struct_test, false);

	/* Union-by-value kfunc return, compiler-version independent. */
	if (test__start_subtest("union"))
		run_prog(skel_run->progs.aggregate_ret_union_test, false);

	aggregate_ret_run__destroy(skel_run);

	RUN_TESTS(aggregate_ret_func);
	RUN_TESTS(aggregate_ret_kfunc);
}
