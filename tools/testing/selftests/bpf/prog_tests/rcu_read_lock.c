// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates.*/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <test_progs.h>
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
	return;
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
	return;
}

static void test_negative(void)
{
#define NUM_FAILED_PROGS	7
	struct bpf_program *failed_progs[NUM_FAILED_PROGS];
	struct rcu_read_lock *skel;
	int i, err;

        skel = rcu_read_lock__open();
        if (!ASSERT_OK_PTR(skel, "skel_open"))
                return;

	failed_progs[0] = skel->progs.miss_lock;
	failed_progs[1] = skel->progs.miss_unlock;
	failed_progs[2] = skel->progs.cgrp_incorrect_rcu_region;
	failed_progs[3] = skel->progs.task_incorrect_rcu_region1;
	failed_progs[4] = skel->progs.task_incorrect_rcu_region2;
	failed_progs[5] = skel->progs.inproper_sleepable_helper;
	failed_progs[6] = skel->progs.inproper_sleepable_kfunc;
	for (i = 0; i < NUM_FAILED_PROGS; i++) {
		bpf_program__set_autoload(failed_progs[i], true);
		err = rcu_read_lock__load(skel);
		if (!ASSERT_ERR(err, "skel_load")) {
			rcu_read_lock__destroy(skel);
			return;
		}
		bpf_program__set_autoload(failed_progs[i], false);
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
	if (test__start_subtest("negative_tests"))
		test_negative();

	close(cgroup_fd);
}
