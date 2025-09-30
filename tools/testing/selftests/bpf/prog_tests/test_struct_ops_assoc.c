// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "struct_ops_assoc.skel.h"

static void test_st_ops_assoc(void)
{
	int sys_enter_prog_a_fd, sys_enter_prog_b_fd;
	int syscall_prog_a_fd, syscall_prog_b_fd;
	struct struct_ops_assoc *skel = NULL;
	int err, pid, map_a_fd, map_b_fd;

	skel = struct_ops_assoc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_assoc__open"))
		goto out;

	sys_enter_prog_a_fd = bpf_program__fd(skel->progs.sys_enter_prog_a);
	sys_enter_prog_b_fd = bpf_program__fd(skel->progs.sys_enter_prog_b);
	syscall_prog_a_fd = bpf_program__fd(skel->progs.syscall_prog_a);
	syscall_prog_b_fd = bpf_program__fd(skel->progs.syscall_prog_b);
	map_a_fd = bpf_map__fd(skel->maps.st_ops_map_a);
	map_b_fd = bpf_map__fd(skel->maps.st_ops_map_b);

	err = bpf_prog_assoc_struct_ops(map_a_fd, syscall_prog_a_fd, NULL);
	if (!ASSERT_OK(err, "bpf_prog_assoc_struct_ops"))
		goto out;

	err = bpf_prog_assoc_struct_ops(map_a_fd, sys_enter_prog_a_fd, NULL);
	if (!ASSERT_OK(err, "bpf_prog_assoc_struct_ops"))
		goto out;

	err = bpf_prog_assoc_struct_ops(map_b_fd, syscall_prog_b_fd, NULL);
	if (!ASSERT_OK(err, "bpf_prog_assoc_struct_ops"))
		goto out;

	err = bpf_prog_assoc_struct_ops(map_b_fd, sys_enter_prog_b_fd, NULL);
	if (!ASSERT_OK(err, "bpf_prog_assoc_struct_ops"))
		goto out;

	/* sys_enter_prog_a already associated with map_a */
	err = bpf_prog_assoc_struct_ops(map_b_fd, sys_enter_prog_a_fd, NULL);
	if (!ASSERT_ERR(err, "bpf_prog_assoc_struct_ops"))
		goto out;

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
	err = bpf_prog_test_run_opts(syscall_prog_a_fd, NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	err = bpf_prog_test_run_opts(syscall_prog_b_fd, NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	ASSERT_EQ(skel->bss->test_err_a, 0, "skel->bss->test_err");
	ASSERT_EQ(skel->bss->test_err_b, 0, "skel->bss->test_err");

out:
	struct_ops_assoc__destroy(skel);
}

void test_struct_ops_assoc(void)
{
	if (test__start_subtest("st_ops_assoc"))
		test_st_ops_assoc();
}
