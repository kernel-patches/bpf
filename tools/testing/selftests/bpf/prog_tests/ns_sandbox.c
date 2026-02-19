// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner <brauner@kernel.org> */

/*
 * Test BPF LSM namespace sandbox: once you enter, you stay.
 *
 * The parent creates a tracked namespace, then forks a child.
 * The child enters the tracked namespace (allowed) and is then locked
 * out of any further setns().
 */

#define _GNU_SOURCE
#include <test_progs.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include "test_ns_sandbox.skel.h"

void test_ns_sandbox(void)
{
	int orig_utsns = -1, new_utsns = -1;
	struct test_ns_sandbox *skel = NULL;
	int err, status;
	pid_t child;

	/* Save FD to current (host) namespace */
	orig_utsns = open("/proc/self/ns/uts", O_RDONLY);
	if (!ASSERT_OK_FD(orig_utsns, "open orig utsns"))
		goto close_fds;

	skel = test_ns_sandbox__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto close_fds;

	err = test_ns_sandbox__attach(skel);
	if (!ASSERT_OK(err, "skel attach"))
		goto destroy;

	skel->bss->monitor_pid = getpid();

	/*
	 * Create a sandbox namespace.  The alloc hook records its
	 * inum because this task's pid matches monitor_pid.
	 */
	err = unshare(CLONE_NEWUTS);
	if (!ASSERT_OK(err, "unshare sandbox"))
		goto destroy;

	new_utsns = open("/proc/self/ns/uts", O_RDONLY);
	if (!ASSERT_OK_FD(new_utsns, "open sandbox utsns"))
		goto restore;

	/*
	 * Return parent to host namespace.  The host namespace is not
	 * in the map so the install hook lets us through.
	 */
	err = setns(orig_utsns, CLONE_NEWUTS);
	if (!ASSERT_OK(err, "parent setns host utsns"))
		goto restore;

	/*
	 * Fork a child that:
	 *  1. Enters the sandbox UTS namespace — succeeds and locks it.
	 *  2. Tries to switch to host UTS — denied (locked).
	 */
	child = fork();
	if (child == 0) {
		/* Enter tracked namespace — allowed, we get locked */
		if (setns(new_utsns, CLONE_NEWUTS) != 0)
			_exit(1);

		/* Locked: switching to host must fail */
		if (setns(orig_utsns, CLONE_NEWUTS) != -1 ||
		    errno != EPERM)
			_exit(2);

		_exit(0);
	}
	if (!ASSERT_GE(child, 0, "fork child"))
		goto restore;

	err = waitpid(child, &status, 0);
	ASSERT_GT(err, 0, "waitpid child");
	ASSERT_TRUE(WIFEXITED(status), "child exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child locked in");

	goto destroy;

restore:
	setns(orig_utsns, CLONE_NEWUTS);
destroy:
	test_ns_sandbox__destroy(skel);
close_fds:
	if (new_utsns >= 0)
		close(new_utsns);
	if (orig_utsns >= 0)
		close(orig_utsns);
}
