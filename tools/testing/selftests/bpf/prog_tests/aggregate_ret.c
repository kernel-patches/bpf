// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "aggregate_ret_int128_c.skel.h"
#include "aggregate_ret_struct_c.skel.h"
#include "aggregate_ret_union_c.skel.h"
#include "aggregate_ret_kfunc_c.skel.h"

/*
 * The bpf_testmod kfuncs returning more than 8 bytes are only built on x86_64
 * and arm64 (see bpf_testmod.c); everywhere else the tests calling them are
 * skipped.
 */
static bool has_ret_pair_kfuncs(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	return true;
#else
	return false;
#endif
}

static void run_prog(struct bpf_program *prog)
{
	char buf[64] = {};
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .data_in = buf,
		    .data_size_in = sizeof(buf),
		    .repeat = 1,
	);

	prog_fd = bpf_program__fd(prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run"))
		return;

	ASSERT_EQ(topts.retval, 0, "aggregate_ret_result");
}

/*
 * Run @prog as subtest @name. Where the register-pair return is unsupported
 * the subtest reports a skip instead, so that the list of subtests does not
 * depend on the compiler or on the architecture; @prog is unused then and may
 * be NULL, for a caller that could not even open its object.
 */
static void run_subtest(const char *name, struct bpf_program *prog, bool supported)
{
	if (!test__start_subtest(name))
		return;

	if (!supported) {
		test__skip();
		return;
	}

	run_prog(prog);
}

static void test_int128_c(void)
{
	struct aggregate_ret_int128_c *skel;

	skel = aggregate_ret_int128_c__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_int128_c_open_load"))
		return;

	run_subtest("int128_c", skel->progs.aggregate_ret_int128_c_test,
		    skel->rodata->has_reg_pair_ret);

	aggregate_ret_int128_c__destroy(skel);
}

static void test_struct_c(void)
{
	struct aggregate_ret_struct_c *skel;

	skel = aggregate_ret_struct_c__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_struct_c_open_load"))
		return;

	run_subtest("struct_c", skel->progs.aggregate_ret_struct_c_test,
		    skel->rodata->has_reg_pair_ret);

	run_subtest("global_struct_c", skel->progs.aggregate_ret_global_struct_c_test,
		    skel->rodata->has_reg_pair_ret);

	aggregate_ret_struct_c__destroy(skel);
}

static void test_union_c(void)
{
	struct aggregate_ret_union_c *skel;

	skel = aggregate_ret_union_c__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_union_c_open_load"))
		return;

	run_subtest("union_c", skel->progs.aggregate_ret_union_c_test,
		    skel->rodata->has_reg_pair_ret);

	aggregate_ret_union_c__destroy(skel);
}

static void test_kfunc_c(void)
{
	struct aggregate_ret_kfunc_c *skel;
	bool supported;
	int err;

	skel = aggregate_ret_kfunc_c__open();
	if (!ASSERT_OK_PTR(skel, "skel_kfunc_c_open"))
		return;

	supported = skel->rodata->has_reg_pair_ret && has_ret_pair_kfuncs();

	if (supported) {
		/*
		 * Where the JIT cannot hand the second half of a >8-byte kfunc
		 * return back in R0:R2, bpf_add_kfunc_call() rejects the call
		 * with -EOPNOTSUPP. Asking the kernel keeps this test free of a
		 * list of the JITs that can, which would have to be updated as
		 * the rest of them learn.
		 */
		err = aggregate_ret_kfunc_c__load(skel);
		if (err == -EOPNOTSUPP)
			supported = false;
		else if (!ASSERT_OK(err, "skel_kfunc_c_load"))
			goto out;
	}

	run_subtest("kfunc_int128_c", skel->progs.aggregate_ret_kfunc_int128_c_test,
		    supported);

	run_subtest("kfunc_struct_c", skel->progs.aggregate_ret_kfunc_struct_c_test,
		    supported);

out:
	aggregate_ret_kfunc_c__destroy(skel);
}

void test_aggregate_ret(void)
{
	test_int128_c();
	test_struct_c();
	test_union_c();
	test_kfunc_c();
}
