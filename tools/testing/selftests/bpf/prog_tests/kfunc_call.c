// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include <network_helpers.h>
#include "kfunc_call_test.skel.h"
#include "kfunc_call_test.lskel.h"
#include "kfunc_call_test_subprog.skel.h"
#include "kfunc_call_test_subprog.lskel.h"

struct syscall_test_args {
	__u8 data[16];
	size_t size;
};

static void test_main(void)
{
	struct kfunc_call_test_lskel *skel;
	int prog_fd, err;
	struct syscall_test_args args = {
		.size = 10,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, syscall_topts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	skel = kfunc_call_test_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	prog_fd = skel->progs.kfunc_call_test1.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run(test1)");
	ASSERT_EQ(topts.retval, 12, "test1-retval");

	prog_fd = skel->progs.kfunc_call_test2.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run(test2)");
	ASSERT_EQ(topts.retval, 3, "test2-retval");

	prog_fd = skel->progs.kfunc_call_test_ref_btf_id.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run(test_ref_btf_id)");
	ASSERT_EQ(topts.retval, 0, "test_ref_btf_id-retval");

	prog_fd = skel->progs.kfunc_syscall_test.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &syscall_topts);
	ASSERT_OK(err, "bpf_prog_test_run(syscall_test)");
	ASSERT_EQ(syscall_topts.retval, 0, "syscall_test-retval");

	prog_fd = skel->progs.kfunc_syscall_test_fail.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &syscall_topts);
	ASSERT_ERR(err, "bpf_prog_test_run(syscall_test_fail)");
	ASSERT_EQ(syscall_topts.retval, 0, "syscall_test_fail-retval");

	kfunc_call_test_lskel__destroy(skel);
}

static void test_subprog(void)
{
	struct kfunc_call_test_subprog *skel;
	int prog_fd, err;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	skel = kfunc_call_test_subprog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	prog_fd = bpf_program__fd(skel->progs.kfunc_call_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run(test1)");
	ASSERT_EQ(topts.retval, 10, "test1-retval");
	ASSERT_NEQ(skel->data->active_res, -1, "active_res");
	ASSERT_EQ(skel->data->sk_state_res, BPF_TCP_CLOSE, "sk_state_res");

	kfunc_call_test_subprog__destroy(skel);
}

static void test_subprog_lskel(void)
{
	struct kfunc_call_test_subprog_lskel *skel;
	int prog_fd, err;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	skel = kfunc_call_test_subprog_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	prog_fd = skel->progs.kfunc_call_test1.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run(test1)");
	ASSERT_EQ(topts.retval, 10, "test1-retval");
	ASSERT_NEQ(skel->data->active_res, -1, "active_res");
	ASSERT_EQ(skel->data->sk_state_res, BPF_TCP_CLOSE, "sk_state_res");

	kfunc_call_test_subprog_lskel__destroy(skel);
}

static void test_get_mem(void)
{
	struct kfunc_call_test *skel;
	int prog_fd, err;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	skel = kfunc_call_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	prog_fd = bpf_program__fd(skel->progs.kfunc_call_test_get_mem);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run(test_get_mem)");
	ASSERT_EQ(topts.retval, 42, "test_get_mem-retval");

	kfunc_call_test__destroy(skel);

	/* start the various failing tests */
	skel = kfunc_call_test__open();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	bpf_program__set_autoload(skel->progs.kfunc_call_test_get_mem_fail1, true);
	err = kfunc_call_test__load(skel);
	ASSERT_ERR(err, "load(kfunc_call_test_get_mem_fail1)");
	kfunc_call_test__destroy(skel);

	skel = kfunc_call_test__open();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	bpf_program__set_autoload(skel->progs.kfunc_call_test_get_mem_fail2, true);
	err = kfunc_call_test__load(skel);
	ASSERT_ERR(err, "load(kfunc_call_test_get_mem_fail2)");

	kfunc_call_test__destroy(skel);
}

void test_kfunc_call(void)
{
	if (test__start_subtest("main"))
		test_main();

	if (test__start_subtest("subprog"))
		test_subprog();

	if (test__start_subtest("subprog_lskel"))
		test_subprog_lskel();

	if (test__start_subtest("get_mem"))
		test_get_mem();
}
