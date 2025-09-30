// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "struct_ops_assoc1.skel.h"
#include "struct_ops_assoc2.skel.h"
#include "struct_ops_id_ops_mapping1.skel.h"
#include "struct_ops_id_ops_mapping2.skel.h"

static void test_st_ops_assoc(void)
{
	int err, pid, map1_fd, map2_fd, prog1_fd, prog2_fd;
	struct struct_ops_assoc1 *skel1 = NULL;
	struct struct_ops_assoc2 *skel2 = NULL;

	skel1 = struct_ops_assoc1__open_and_load();
	if (!ASSERT_OK_PTR(skel1, "struct_ops_assoc1__open"))
		goto out;

	skel2 = struct_ops_assoc2__open_and_load();
	if (!ASSERT_OK_PTR(skel2, "struct_ops_assoc2__open"))
		goto out;

	map1_fd = bpf_map__fd(skel1->maps.st_ops_map);
	map2_fd = bpf_map__fd(skel2->maps.st_ops_map);

	//err = struct_ops_assoc1__associate_prog(skel1->progs.syscall_prog);
	//err = struct_ops_assoc1__associate_progs();
	prog1_fd = bpf_program__fd(skel1->progs.sys_enter);
	err = bpf_struct_ops_associate_prog(map1_fd, prog1_fd, NULL);
	if (!ASSERT_OK(err, "bpf_struct_ops_associate_prog"))
		goto out;

	prog1_fd = bpf_program__fd(skel1->progs.syscall_prog);
	err = bpf_struct_ops_associate_prog(map1_fd, prog1_fd, NULL);
	if (!ASSERT_OK(err, "bpf_struct_ops_associate_prog"))
		goto out;

	prog2_fd = bpf_program__fd(skel2->progs.sys_enter);
	err = bpf_struct_ops_associate_prog(map2_fd, prog2_fd, NULL);
	if (!ASSERT_OK(err, "bpf_struct_ops_associate_prog"))
		goto out;

	prog2_fd = bpf_program__fd(skel2->progs.syscall_prog);
	err = bpf_struct_ops_associate_prog(map2_fd, prog2_fd, NULL);
	if (!ASSERT_OK(err, "bpf_struct_ops_associate_prog"))
		goto out;

	err = struct_ops_assoc1__attach(skel1);
	if (!ASSERT_OK(err, "struct_ops_assoc1__attach"))
		goto out;

	err = struct_ops_assoc2__attach(skel2);
	if (!ASSERT_OK(err, "struct_ops_assoc2__attach"))
		goto out;

	/* run tracing prog that calls .test_1 and checks return */
	pid = getpid();
	skel1->bss->test_pid = pid;
	skel2->bss->test_pid = pid;
	sys_gettid();
	skel1->bss->test_pid = 0;
	skel2->bss->test_pid = 0;

	ASSERT_EQ(skel1->bss->test_err, 0, "skel1->bss->test_err");
	ASSERT_EQ(skel2->bss->test_err, 0, "skel2->bss->test_err");

	/* run syscall_prog that calls .test_1 and checks return */
	err = bpf_prog_test_run_opts(prog1_fd, NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	err = bpf_prog_test_run_opts(prog2_fd, NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	ASSERT_EQ(skel1->bss->test_err, 0, "skel1->bss->test_err");
	ASSERT_EQ(skel2->bss->test_err, 0, "skel2->bss->test_err");

out:
	struct_ops_assoc1__destroy(skel1);
	struct_ops_assoc2__destroy(skel2);
}

static void test_st_ops_id_ops_mapping(void)
{
	struct struct_ops_id_ops_mapping1 *skel1 = NULL;
	struct struct_ops_id_ops_mapping2 *skel2 = NULL;
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	int err, pid, prog1_fd, prog2_fd;

	skel1 = struct_ops_id_ops_mapping1__open_and_load();
	if (!ASSERT_OK_PTR(skel1, "struct_ops_id_ops_mapping1__open"))
		goto out;

	skel2 = struct_ops_id_ops_mapping2__open_and_load();
	if (!ASSERT_OK_PTR(skel2, "struct_ops_id_ops_mapping2__open"))
		goto out;

	err = bpf_map_get_info_by_fd(bpf_map__fd(skel1->maps.st_ops_map),
				     &info, &len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto out;

	skel1->bss->st_ops_id = info.id;

	err = bpf_map_get_info_by_fd(bpf_map__fd(skel2->maps.st_ops_map),
				     &info, &len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto out;

	skel2->bss->st_ops_id = info.id;

	err = struct_ops_id_ops_mapping1__attach(skel1);
	if (!ASSERT_OK(err, "struct_ops_id_ops_mapping1__attach"))
		goto out;

	err = struct_ops_id_ops_mapping2__attach(skel2);
	if (!ASSERT_OK(err, "struct_ops_id_ops_mapping2__attach"))
		goto out;

	/* run tracing prog that calls .test_1 and checks return */
	pid = getpid();
	skel1->bss->test_pid = pid;
	skel2->bss->test_pid = pid;
	sys_gettid();
	skel1->bss->test_pid = 0;
	skel2->bss->test_pid = 0;

	/* run syscall_prog that calls .test_1 and checks return */
	prog1_fd = bpf_program__fd(skel1->progs.syscall_prog);
	err = bpf_prog_test_run_opts(prog1_fd, NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	prog2_fd = bpf_program__fd(skel2->progs.syscall_prog);
	err = bpf_prog_test_run_opts(prog2_fd, NULL);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	ASSERT_EQ(skel1->bss->test_err, 0, "skel1->bss->test_err");
	ASSERT_EQ(skel2->bss->test_err, 0, "skel2->bss->test_err");

out:
	struct_ops_id_ops_mapping1__destroy(skel1);
	struct_ops_id_ops_mapping2__destroy(skel2);
}

void test_struct_ops_id_ops_mapping(void)
{
	if (test__start_subtest("st_ops_id_ops_mapping"))
		test_st_ops_id_ops_mapping();
	if (test__start_subtest("st_ops_assoc"))
		test_st_ops_assoc();
}
