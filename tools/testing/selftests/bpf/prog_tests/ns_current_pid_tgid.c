// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Carlos Neira cneirabustos@gmail.com */

#define _GNU_SOURCE
#include <test_progs.h>
#include "test_ns_current_pid_tgid.skel.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/fcntl.h>

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

static void test_ns_current_pid_tgid_global_ns(void)
{
	struct test_ns_current_pid_tgid__bss  *bss;
	struct test_ns_current_pid_tgid *skel;
	int err, duration = 0;
	struct stat st;
	pid_t tgid, pid;

	skel = test_ns_current_pid_tgid__open_and_load();
	if (CHECK(!skel, "skel_open_load", "failed to load skeleton\n"))
		goto cleanup;

	pid = syscall(SYS_gettid);
	tgid = getpid();

	err = stat("/proc/self/ns/pid", &st);
	if (CHECK(err, "stat", "failed /proc/self/ns/pid: %d\n", err))
		goto cleanup;

	bss = skel->bss;
	bss->dev = st.st_dev;
	bss->ino = st.st_ino;
	bss->user_pid= 0;
	bss->user_tgid = 0;

	err = test_ns_current_pid_tgid__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger tracepoint */
	usleep(1);
	ASSERT_EQ(bss->user_pid, pid, "pid");
	ASSERT_EQ(bss->user_tgid, tgid, "tgid");

cleanup:
	 test_ns_current_pid_tgid__destroy(skel);
}

static int newns_pidtgid(void *arg)
{
	struct test_ns_current_pid_tgid__bss  *bss;
	int err = 0, duration = 0;
	struct test_ns_current_pid_tgid *skel;
	pid_t pid, tgid;
	struct stat st;

	skel = test_ns_current_pid_tgid__open_and_load();
	if (CHECK(!skel, "skel_open_load", "failed to load skeleton\n"))
		goto cleanup;

	pid = syscall(SYS_gettid);
	tgid = getpid();

	err = stat("/proc/self/ns/pid", &st);
	if (CHECK(err, "stat", "failed /proc/self/ns/pid: %d\n", err))
		goto cleanup;

	bss = skel->bss;
	bss->dev = st.st_dev;
	bss->ino = st.st_ino;
	bss->user_pid = 0;
	bss->user_tgid = 0;

	err = test_ns_current_pid_tgid__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger tracepoint */
	usleep(1);
	ASSERT_EQ(bss->user_pid, pid, "pid");
	ASSERT_EQ(bss->user_tgid, tgid, "tgid");

cleanup:
	 test_ns_current_pid_tgid__destroy(skel);

	return err;
}

static void test_ns_current_pid_tgid_new_ns(void)
{
	int wstatus, duration = 0;
	pid_t cpid;
	/* Create a process in a new namespace, this process
	 * will be the init process of this new namespace hence will be pid 1.
	 */
	cpid = clone(newns_pidtgid,
	  child_stack + STACK_SIZE,
	  CLONE_NEWPID | SIGCHLD, NULL);

	if (CHECK(cpid == -1, "clone", strerror(errno)))
		exit(EXIT_FAILURE);

	if (CHECK(waitpid(cpid, &wstatus, 0) == -1, "waitpid",
	 strerror(errno)))
		exit(EXIT_FAILURE);

	if (CHECK(WEXITSTATUS(wstatus) != 0, "newns_pidtgid",
	 "failed"))
		exit(EXIT_FAILURE);
}

void test_ns_current_pid_tgid(void)
{
	if (test__start_subtest("ns_current_pid_tgid_global_ns"))
		test_ns_current_pid_tgid_global_ns();
	if (test__start_subtest("ns_current_pid_tgid_new_ns"))
		test_ns_current_pid_tgid_new_ns();
}
