// SPDX-License-Identifier: GPL-2.0

#include <sys/syscall.h>
#include <test_progs.h>
#include <cgroup_helpers.h>
#include <unistd.h>
#include "test_task_freeze_cgroup.skel.h"

#define CGROUP_PATH	"/test-task-freeze-cgroup"

static int bpf_sleepable(struct test_task_freeze_cgroup *skel)
{
	int err, cgroup_fd;
	pid_t new_pid2;

	cgroup_fd = cgroup_setup_and_join(CGROUP_PATH);
	if (!ASSERT_OK(cgroup_fd < 0, "cgroup_setup_and_join"))
		return -errno;

	skel = test_task_freeze_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "test_task_freeze_cgroup__open")) {
		err = -errno;
		goto cleanup_cgroup;
	}

	skel->rodata->parent_pid = getppid();
	skel->rodata->monitor_pid = getpid();
	skel->rodata->cgid = get_cgroup_id(CGROUP_PATH);
	skel->bss->new_pid = getpid();
	skel->bss->freeze = 1;

	err = test_task_freeze_cgroup__load(skel);
	if (!ASSERT_OK(err, "test_task_freeze_cgroup__load")) {
		err = -errno;
		goto cleanup_skel;
	}

	/* First attach the LSM Program that is triggered on bpf() calls
	 * especially on TP_BTF programs when attached.
	 */
	skel->links.lsm_freeze_cgroup =
		bpf_program__attach_lsm(skel->progs.lsm_freeze_cgroup);
	if (!ASSERT_OK_PTR(skel->links.lsm_freeze_cgroup, "attach_lsm")) {
		err = -errno;
		goto cleanup_detach;
	}

	/* Attaching this must fail with -EPERM and freeze current task */
	skel->links.tp_newchild =
		bpf_program__attach_trace(skel->progs.tp_newchild);
	if (!ASSERT_EQ(errno, EPERM, "attach_trace() must fail here")) {
		err = -EINVAL;
		goto cleanup_detach;
	}

	/* Continue */

	/* Attach again now with success */
	skel->links.tp_newchild =
		bpf_program__attach_trace(skel->progs.tp_newchild);
	if (!ASSERT_OK_PTR(skel->links.tp_newchild, "attach_trace")) {
		err = -EINVAL;
		goto cleanup_detach;
	}

	/* Fork, update vars from BPF and assert the unfrozen state */
	new_pid2 = fork();
	if (new_pid2 == 0)
		exit(0);

	err = (new_pid2 == -1);
	if (ASSERT_OK(err, "fork process"))
		wait(NULL);

	/* Now assert that new_pid2 reflects this new child */
	ASSERT_NEQ(0, skel->bss->new_pid,
		   "test task_freeze_cgroup failed  at new_pid != 0");
	ASSERT_NEQ(skel->rodata->monitor_pid, skel->bss->new_pid,
		   "test task_freeze_cgroup failed  at old monitor_pid != new_pid");
	/* Assert that bpf sets new_pid to new forked child new_pid2 */
	ASSERT_EQ(skel->bss->new_pid, new_pid2,
		  "test task_freeze_cgroup failed first child new_pid == new_pid2");

cleanup_detach:
	test_task_freeze_cgroup__detach(skel);
cleanup_skel:
	test_task_freeze_cgroup__destroy(skel);
cleanup_cgroup:
	close(cgroup_fd);
	cleanup_cgroup_environment();
	return err;
}

void test_task_freeze_cgroup(void)
{
	pid_t pid, result;
	char buf[512] = {0};
	char path[PATH_MAX] = {0};
	int ret, status, attempts, frozen = 0, fd;
	struct test_task_freeze_cgroup *skel = NULL;

	pid = fork();
	ret = (pid == -1);
	if (!ASSERT_OK(ret, "fork process"))
		return;

	if (pid == 0) {
		ret = bpf_sleepable(skel);
		ASSERT_EQ(0, ret, "child bpf_sleepable failed");
		exit(ret);
	}

	skel = test_task_freeze_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "test_task_freeze_cgroup__open"))
		goto out;

	snprintf(path, sizeof(path),
		 "/sys/fs/cgroup/cgroup-test-work-dir%d%s/cgroup.freeze",
		 pid, CGROUP_PATH);

	for (attempts = 10; attempts >= 0; attempts--) {
		ret = 0;

		fd = open(path, O_RDONLY);
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

	/* Trigger the unthaw child cgroup from parent */
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
