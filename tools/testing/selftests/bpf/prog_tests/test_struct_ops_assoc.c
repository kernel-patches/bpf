// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "struct_ops_assoc.skel.h"
#include "struct_ops_assoc_reuse.skel.h"
#include "struct_ops_assoc_in_timer.skel.h"

static void test_st_ops_assoc(void)
{
	struct struct_ops_assoc *skel = NULL;
	int err, pid;

	skel = struct_ops_assoc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_assoc__open"))
		goto out;

	/* cannot explicitly associate struct_ops program */
	err = bpf_program__assoc_struct_ops(skel->progs.test_1_a,
					    skel->maps.st_ops_map_a, NULL);
	ASSERT_ERR(err, "bpf_program__assoc_struct_ops");

	err = bpf_program__assoc_struct_ops(skel->progs.syscall_prog_a,
					    skel->maps.st_ops_map_a, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	err = bpf_program__assoc_struct_ops(skel->progs.sys_enter_prog_a,
					    skel->maps.st_ops_map_a, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	err = bpf_program__assoc_struct_ops(skel->progs.syscall_prog_b,
					    skel->maps.st_ops_map_b, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	err = bpf_program__assoc_struct_ops(skel->progs.sys_enter_prog_b,
					    skel->maps.st_ops_map_b, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	/* sys_enter_prog_a already associated with map_a */
	err = bpf_program__assoc_struct_ops(skel->progs.sys_enter_prog_a,
					    skel->maps.st_ops_map_b, NULL);
	ASSERT_ERR(err, "bpf_program__assoc_struct_ops");

	err = struct_ops_assoc__attach(skel);
	if (!ASSERT_OK(err, "struct_ops_assoc__attach"))
		goto out;

	/* run tracing prog that calls .test_1 and checks return */
	pid = getpid();
	skel->bss->test_pid = pid;
	sys_gettid();
	skel->bss->test_pid = 0;

	ASSERT_EQ(skel->bss->test_err_a, 0, "skel->bss->test_err_a");
	ASSERT_EQ(skel->bss->test_err_b, 0, "skel->bss->test_err_b");

	/* run syscall_prog that calls .test_1 and checks return */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.syscall_prog_a), NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.syscall_prog_b), NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	ASSERT_EQ(skel->bss->test_err_a, 0, "skel->bss->test_err_a");
	ASSERT_EQ(skel->bss->test_err_b, 0, "skel->bss->test_err_b");

out:
	struct_ops_assoc__destroy(skel);
}

static void test_st_ops_assoc_reuse(void)
{
	struct struct_ops_assoc_reuse *skel = NULL;
	int err;

	skel = struct_ops_assoc_reuse__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_assoc_reuse__open"))
		goto out;

	err = bpf_program__assoc_struct_ops(skel->progs.syscall_prog_a,
					    skel->maps.st_ops_map_a, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	err = bpf_program__assoc_struct_ops(skel->progs.syscall_prog_b,
					    skel->maps.st_ops_map_b, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	err = struct_ops_assoc_reuse__attach(skel);
	if (!ASSERT_OK(err, "struct_ops_assoc__attach"))
		goto out;

	/* run syscall_prog that calls .test_1 and checks return */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.syscall_prog_a), NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.syscall_prog_b), NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	ASSERT_EQ(skel->bss->test_err_a, 0, "skel->bss->test_err_a");
	ASSERT_EQ(skel->bss->test_err_b, 0, "skel->bss->test_err_b");

out:
	struct_ops_assoc_reuse__destroy(skel);
}

static void test_st_ops_assoc_in_timer(void)
{
	struct struct_ops_assoc_in_timer *skel = NULL;
	int err;

	skel = struct_ops_assoc_in_timer__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_assoc_reuse__open"))
		goto out;

	err = bpf_program__assoc_struct_ops(skel->progs.syscall_prog,
					    skel->maps.st_ops_map, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	err = struct_ops_assoc_in_timer__attach(skel);
	if (!ASSERT_OK(err, "struct_ops_assoc__attach"))
		goto out;

	/* run syscall_prog that calls .test_1 and checks return */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.syscall_prog), NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	/*
	 * .test_1 has scheduled timer_cb that calls bpf_kfunc_multi_st_ops_test_1_prog_arg()
	 * again. Check the return of the kfunc after timer_cb run.
	 */
	while (!READ_ONCE(skel->bss->timer_cb_run))
		sched_yield();
	ASSERT_EQ(skel->bss->timer_test_1_ret, 1234, "skel->bss->timer_test_1_ret");
	ASSERT_EQ(skel->bss->test_err, 0, "skel->bss->test_err_a");
out:
	struct_ops_assoc_in_timer__destroy(skel);
}

static void test_st_ops_assoc_in_timer_after_detach(void)
{
	struct struct_ops_assoc_in_timer *skel = NULL;
	struct bpf_link *link;
	int err;

	skel = struct_ops_assoc_in_timer__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_assoc_reuse__open"))
		goto out;

	err = bpf_program__assoc_struct_ops(skel->progs.syscall_prog,
					    skel->maps.st_ops_map, NULL);
	ASSERT_OK(err, "bpf_program__assoc_struct_ops");

	link = bpf_map__attach_struct_ops(skel->maps.st_ops_map);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;

	/* timer_cb will run 500ms after syscall_prog_run when st_ops_map is gone */
	skel->bss->timer_ns = 500000000;

	/* run syscall_prog that calls .test_1 and checks return */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.syscall_prog), NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	/* detach and free struct_ops map */
	bpf_link__destroy(link);
	close(bpf_program__fd(skel->progs.syscall_prog));
	close(bpf_map__fd(skel->maps.st_ops_map));

	/*
	 * .test_1 has scheduled timer_cb that calls bpf_kfunc_multi_st_ops_test_1_prog_arg()
	 * again. Check the return of the kfunc after timer_cb run.
	 */
	while (!READ_ONCE(skel->bss->timer_cb_run))
		sched_yield();
	ASSERT_EQ(skel->bss->timer_test_1_ret, -1, "skel->bss->timer_test_1_ret");
	ASSERT_EQ(skel->bss->test_err, 0, "skel->bss->test_err_a");
out:
	struct_ops_assoc_in_timer__destroy(skel);
}

void test_struct_ops_assoc(void)
{
	if (test__start_subtest("st_ops_assoc"))
		test_st_ops_assoc();
	if (test__start_subtest("st_ops_assoc_reuse"))
		test_st_ops_assoc_reuse();
	if (test__start_subtest("st_ops_assoc_in_timer"))
		test_st_ops_assoc_in_timer();
	if (test__start_subtest("st_ops_assoc_in_timer_after_detach"))
		test_st_ops_assoc_in_timer_after_detach();
}
