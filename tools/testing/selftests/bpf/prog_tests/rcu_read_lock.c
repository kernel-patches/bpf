// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates.*/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include "rcu_read_lock.skel.h"

static void test_local_storage(void)
{
	struct rcu_read_lock *skel;
	int err;

	skel = rcu_read_lock__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->target_pid = syscall(SYS_gettid);

	bpf_program__set_autoload(skel->progs.cgrp_succ, true);
	bpf_program__set_autoload(skel->progs.task_succ, true);
	bpf_program__set_autoload(skel->progs.two_regions, true);
	bpf_program__set_autoload(skel->progs.non_sleepable_1, true);
	bpf_program__set_autoload(skel->progs.non_sleepable_2, true);
	err = rcu_read_lock__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto done;

	err = rcu_read_lock__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto done;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->result, 2, "result");
done:
	rcu_read_lock__destroy(skel);
}

static void test_runtime_diff_rcu_tag(void)
{
	struct rcu_read_lock *skel;
	int err;

	skel = rcu_read_lock__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bpf_program__set_autoload(skel->progs.dump_ipv6_route, true);
	err = rcu_read_lock__load(skel);
	ASSERT_OK(err, "skel_load");
	rcu_read_lock__destroy(skel);
}

static void test_negative_region(void)
{
#define NUM_REGION_FAILED_PROGS		6
	struct rcu_read_lock *skel;
	struct bpf_program *prog;
	int i, err;

	for (i = 0; i < NUM_REGION_FAILED_PROGS; i++) {
		skel = rcu_read_lock__open();
		if (!ASSERT_OK_PTR(skel, "skel_open"))
			return;

		switch (i) {
		case 0:
			prog = skel->progs.miss_lock;
			break;
		case 1:
			prog = skel->progs.miss_unlock;
			break;
		case 2:
			prog = skel->progs.non_sleepable_rcu_mismatch;
			break;
		case 3:
			prog = skel->progs.inproper_sleepable_helper;
			break;
		case 4:
			prog = skel->progs.inproper_sleepable_kfunc;
			break;
		default:
			prog = skel->progs.nested_rcu_region;
			break;
		}

		bpf_program__set_autoload(prog, true);
		err = rcu_read_lock__load(skel);
		if (!ASSERT_ERR(err, "skel_load")) {
			rcu_read_lock__destroy(skel);
			return;
		}
	}
}

static void test_negative_rcuptr_misuse(void)
{
#define NUM_RCUPTR_FAILED_PROGS		4
	struct rcu_read_lock *skel;
	struct bpf_program *prog;
	struct btf *vmlinux_btf;
	int i, err, type_id;

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "could not load vmlinux BTF"))
		return;

	/* skip the test if btf_type_tag("rcu") is not present in vmlinux */
	type_id = btf__find_by_name_kind(vmlinux_btf, "rcu", BTF_KIND_TYPE_TAG);
	if (type_id < 0) {
		test__skip();
		return;
	}

	for (i = 0; i < NUM_RCUPTR_FAILED_PROGS; i++) {
		skel = rcu_read_lock__open();
		if (!ASSERT_OK_PTR(skel, "skel_open"))
			return;

		switch (i) {
		case 0:
			prog = skel->progs.cgrp_incorrect_rcu_region;
			break;
		case 1:
			prog = skel->progs.task_incorrect_rcu_region1;
			break;
		case 2:
			prog = skel->progs.task_incorrect_rcu_region2;
			break;
		default:
			prog = skel->progs.cross_rcu_region;
			break;
		}

		bpf_program__set_autoload(prog, true);
		err = rcu_read_lock__load(skel);
		if (!ASSERT_ERR(err, "skel_load")) {
			rcu_read_lock__destroy(skel);
			return;
		}
	}
}

void test_rcu_read_lock(void)
{
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/rcu_read_lock");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup /rcu_read_lock"))
		return;

	if (test__start_subtest("local_storage"))
		test_local_storage();
	if (test__start_subtest("runtime_diff_rcu_tag"))
		test_runtime_diff_rcu_tag();
	if (test__start_subtest("negative_tests_region"))
		test_negative_region();
	if (test__start_subtest("negative_tests_rcuptr_misuse"))
		test_negative_rcuptr_misuse();

	close(cgroup_fd);
}
