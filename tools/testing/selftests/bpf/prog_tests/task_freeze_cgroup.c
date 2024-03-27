// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <sys/syscall.h>
#include <test_progs.h>
#include <cgroup_helpers.h>
#include <unistd.h>
#include "test_task_freeze_cgroup.skel.h"

#define FOO	"/test-task-freeze-cgroup"

static int bpf_sleepable(struct test_task_freeze_cgroup *skel)
{
	int err, foo;
	pid_t pid;

	foo = test__join_cgroup(FOO);
	if (!ASSERT_OK(foo < 0, "cgroup_join_foo"))
		return -errno;

	skel = test_task_freeze_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "test_task_freeze_cgroup__open"))
		return -errno;

	skel->rodata->parent_pid = getppid();
	skel->rodata->monitor_pid = getpid();
	skel->rodata->cgid = get_cgroup_id(FOO);
	skel->bss->new_pid = getpid();
	skel->bss->freeze = 1;

	err = test_task_freeze_cgroup__load(skel);
	if (!ASSERT_OK(err, "test_task_freeze_cgroup__load"))
		goto cleanup;

	/* First, attach the LSM program, and then it will be triggered when the
	 * TP_BTF program is attached.
	 */
	skel->links.lsm_freeze_cgroup =
		bpf_program__attach_lsm(skel->progs.lsm_freeze_cgroup);
	if (!ASSERT_OK_PTR(skel->links.lsm_freeze_cgroup, "attach_lsm")) {
		err = -errno;
		goto cleanup;
	}

	/* This will fail */
	skel->links.tp_newchild =
		bpf_program__attach_trace(skel->progs.tp_newchild);
	if (!ASSERT_EQ(errno, EPERM, "attach_trace")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* Try again now */
	skel->links.tp_newchild =
		bpf_program__attach_trace(skel->progs.tp_newchild);
	if (!ASSERT_OK_PTR(skel->links.tp_newchild, "attach_trace")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* Trigger a new child and assert unfrozen state */
	pid = fork();
	if (pid == 0)
		exit(0);

	err = (pid == -1);
	if (ASSERT_OK(err, "fork process"))
		wait(NULL);

	/* Now we should continue, assert that new_pid reflects child */
	ASSERT_NEQ(skel->rodata->monitor_pid, skel->bss->new_pid,
		   "test task_freeze_cgroup failed  at monitor_pid != new_pid");
	ASSERT_NEQ(0, skel->bss->new_pid,
		   "test task_freeze_cgroup failed  at remote_pid != 0");

	/* Assert that bpf set new_pid to new forked child pid */
	ASSERT_EQ(pid, skel->bss->new_pid,
		   "test task_freeze_cgroup failed  at pid == new_pid");

	test_task_freeze_cgroup__detach(skel);

cleanup:
	test_task_freeze_cgroup__destroy(skel);
	close(foo);
	return err;
}

void test_task_freeze_cgroup(void)
{
	pid_t pid, result;
	char buf[512] = {0};
	char path[PATH_MAX] = {0};
	int ret, status, attempts, frozen = 0;
	struct test_task_freeze_cgroup *skel = NULL;

	pid = fork();
	ret = (pid == -1);
	if (!ASSERT_OK(ret, "fork process"))
		return;

	if (pid == 0) {
		ret = bpf_sleepable(skel);
		ASSERT_EQ(0, ret, "bpf_sleepable failed");
		exit(ret);
	}

	skel = test_task_freeze_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "test_task_freeze_cgroup__open"))
		goto out;

	snprintf(path, sizeof(path),
		 "/sys/fs/cgroup/cgroup-test-work-dir%d%s/cgroup.freeze",
		 pid, FOO);

	for (attempts = 5; attempts >= 0; attempts--) {
		ret = 0;
		int fd = open(path, O_RDONLY);
		if (fd > 0)
			ret = read(fd, buf, sizeof(buf) - 1);
		if (ret > 0) {
			errno = 0;
			frozen = strtol(buf, NULL, 10);
			if (errno)
				frozen = 0;
		}

		close(fd);
		if (frozen)
			break;
		sleep(1);
	}

	/* Assert that child cgroup is frozen */
	if (!ASSERT_EQ(1, frozen, "child cgroup not frozen"))
		goto out;

	ret = test_task_freeze_cgroup__load(skel);
	if (!ASSERT_OK(ret, "test_task_freeze_cgroup__load"))
		goto out;

	/* Unthaw child cgroup from parent */
	skel->links.lsm_task_free =
		bpf_program__attach_lsm(skel->progs.lsm_task_free);
	if (!ASSERT_OK_PTR(skel->links.lsm_task_free, "attach_lsm"))
		goto out;

	result = waitpid(pid, &status, WUNTRACED);
	if (!ASSERT_NEQ(result, -1, "waitpid"))
		goto detach;

	result = WIFEXITED(status);
	if (!ASSERT_EQ(result, 1, "forked process did not terminate normally"))
		goto detach;

	result = WEXITSTATUS(status);
	if (!ASSERT_EQ(result, 0, "forked process did not exit successfully"))
		goto detach;

detach:
	test_task_freeze_cgroup__detach(skel);

out:
	if (skel)
		test_task_freeze_cgroup__destroy(skel);
}
