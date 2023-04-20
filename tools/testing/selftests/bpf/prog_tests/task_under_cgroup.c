// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Bytedance */

#include <test_progs.h>
#include "test_task_under_cgroup.skel.h"

#define FOO	"/foo"

void test_task_under_cgroup(void)
{
	struct test_task_under_cgroup *skel;
	int ret, foo = -1, idx = 0;

	skel = test_task_under_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "test_task_under_cgroup__open"))
		return;

	skel->rodata->local_pid = getpid();

	ret = test_task_under_cgroup__load(skel);
	if (!ASSERT_OK(ret, "test_task_under_cgroup__load"))
		goto cleanup;

	ret = test_task_under_cgroup__attach(skel);
	if (!ASSERT_OK(ret, "test_task_under_cgroup__attach"))
		goto cleanup;

	foo = test__join_cgroup(FOO);
	if (!ASSERT_OK(foo < 0, "cgroup_join_foo"))
		goto cleanup;

	ret = bpf_map_update_elem(bpf_map__fd(skel->maps.cgroup_map), &idx,
				  &foo, BPF_ANY);
	if (!ASSERT_OK(ret < 0, "cgroup_map update"))
		goto cleanup;

	syscall(__NR_getuid);

	test_task_under_cgroup__detach(skel);

	ASSERT_EQ(skel->bss->remote_pid, skel->rodata->local_pid,
		  "test task_under_cgroup");

cleanup:
	if (foo)
		close(foo);

	test_task_under_cgroup__destroy(skel);
}
