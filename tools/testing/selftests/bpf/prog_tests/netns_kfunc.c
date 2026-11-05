// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Abhishek Khade */

#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <test_progs.h>
#include "test_netns_kfunc.skel.h"

void test_netns_kfunc(void)
{
	struct test_netns_kfunc *skel;
	int pipefd[2];
	pid_t pid;
	int status = 0;
	u32 host_inum;

	skel = test_netns_kfunc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (!ASSERT_OK(test_netns_kfunc__attach(skel), "attach"))
		goto cleanup;

	/* Test 1: Process running in initial network namespace */
	if (!ASSERT_OK(pipe(pipefd), "pipe_init"))
		goto cleanup;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork_host")) {
		close(pipefd[0]);
		close(pipefd[1]);
		goto cleanup;
	}

	if (pid == 0) {
		close(pipefd[1]);
		if (read(pipefd[0], &status, sizeof(status)) < 0)
			exit(1);
		close(pipefd[0]);
		execlp("true", "true", NULL);
		exit(1);
	}

	skel->bss->target_pid = pid;
	close(pipefd[0]);
	if (write(pipefd[1], &status, sizeof(status)) < 0) {
		close(pipefd[1]);
		waitpid(pid, NULL, 0);
		goto cleanup;
	}
	close(pipefd[1]);
	waitpid(pid, &status, 0);

	ASSERT_EQ(skel->bss->inv_is_init_net, 1, "host_task_is_init_net");
	ASSERT_GT(skel->bss->inv_netns_inum, 0, "host_netns_inum_valid");
	host_inum = skel->bss->inv_netns_inum;

	/* Reset state */
	skel->bss->inv_is_init_net = -1;
	skel->bss->inv_netns_inum = 0;

	/* Test 2: Process running in a new network namespace */
	if (!ASSERT_OK(pipe(pipefd), "pipe_netns"))
		goto cleanup;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork_netns")) {
		close(pipefd[0]);
		close(pipefd[1]);
		goto cleanup;
	}

	if (pid == 0) {
		close(pipefd[1]);
		if (read(pipefd[0], &status, sizeof(status)) < 0)
			exit(1);
		close(pipefd[0]);

		if (unshare(CLONE_NEWNET) != 0)
			exit(1);

		execlp("true", "true", NULL);
		exit(1);
	}

	skel->bss->target_pid = pid;
	close(pipefd[0]);
	if (write(pipefd[1], &status, sizeof(status)) < 0) {
		close(pipefd[1]);
		waitpid(pid, NULL, 0);
		goto cleanup;
	}
	close(pipefd[1]);
	waitpid(pid, &status, 0);

	ASSERT_EQ(skel->bss->inv_is_init_net, 0, "netns_task_not_init_net");
	ASSERT_GT(skel->bss->inv_netns_inum, 0, "child_netns_inum_valid");
	ASSERT_NEQ(skel->bss->inv_netns_inum, host_inum, "netns_inum_different");

cleanup:
	test_netns_kfunc__destroy(skel);
}
