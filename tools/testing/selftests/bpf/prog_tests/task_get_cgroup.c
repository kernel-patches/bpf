// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Netflix, Inc.

#include <test_progs.h>
#include <cgroup_helpers.h>
#include "test_task_get_cgroup.skel.h"
#include <unistd.h>

#define TEST_CGROUP "/test-task-get-cgroup/"

void test_task_get_cgroup(void)
{
	struct test_task_get_cgroup *skel;
	int err, fd;
	__u64 expected_cgroup_id;

	fd = test__join_cgroup(TEST_CGROUP);
	if (!ASSERT_OK(fd < 0, "test_join_cgroup_TEST_CGROUP"))
		return;

	skel = test_task_get_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_task_get_cgroup__open_and_load"))
		goto cleanup;

	err = test_task_get_cgroup__attach(skel);
	if (!ASSERT_OK(err, "test_task_get_cgroup__attach"))
		goto cleanup;

	skel->bss->pid = getpid();
	expected_cgroup_id = get_cgroup_id(TEST_CGROUP);
	if (!ASSERT_GT(expected_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	/* Trigger nanosleep to enter the sched_switch tracepoint */
	/* The previous task should be this process */
	usleep(100);

	ASSERT_EQ(skel->bss->cgroup_id, expected_cgroup_id, "cgroup_id");

cleanup:
	test_task_get_cgroup__destroy(skel);
	close(fd);
}
