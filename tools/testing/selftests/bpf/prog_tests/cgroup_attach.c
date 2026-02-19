// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner <brauner@kernel.org> */

/*
 * Test the bpf_lsm_cgroup_attach hook.
 *
 * Verifies that a BPF LSM program can supervise cgroup migration
 * through both the cgroup.procs write path and the clone3 +
 * CLONE_INTO_CGROUP path.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "test_cgroup_attach.skel.h"

/* Must match the definition in progs/test_cgroup_attach.c */
struct attach_event {
	__u32 task_pid;
	__u64 src_cgrp_id;
	__u64 dst_cgrp_id;
	__u8  threadgroup;
	__u32 hook_count;
};

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

struct __clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
	__aligned_u64 set_tid;
	__aligned_u64 set_tid_size;
	__aligned_u64 cgroup;
};

static pid_t do_clone3(int cgroup_fd)
{
	struct __clone_args args = {
		.flags = CLONE_INTO_CGROUP,
		.exit_signal = SIGCHLD,
		.cgroup = cgroup_fd,
	};

	return syscall(__NR_clone3, &args, sizeof(args));
}

/*
 * Subtest: deny_migration
 *
 * Verify that the BPF hook can deny cgroup migration through cgroup.procs
 * and that detaching the BPF program removes enforcement.
 */
static void test_deny_migration(void)
{
	struct test_cgroup_attach *skel = NULL;
	int allowed_fd = -1, denied_fd = -1;
	unsigned long long denied_cgid;
	int err, status;
	__u64 key;
	__u8 val = 1;
	pid_t child;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_env"))
		return;

	allowed_fd = create_and_get_cgroup("/allowed");
	if (!ASSERT_GE(allowed_fd, 0, "create /allowed"))
		goto cleanup;

	denied_fd = create_and_get_cgroup("/denied");
	if (!ASSERT_GE(denied_fd, 0, "create /denied"))
		goto cleanup;

	skel = test_cgroup_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto cleanup;

	err = test_cgroup_attach__attach(skel);
	if (!ASSERT_OK(err, "skel attach"))
		goto cleanup;

	skel->bss->monitored_pid = getpid();

	denied_cgid = get_cgroup_id("/denied");
	if (!ASSERT_NEQ(denied_cgid, 0ULL, "get denied cgroup id"))
		goto cleanup;

	key = denied_cgid;
	err = bpf_map__update_elem(skel->maps.denied_cgroups,
				   &key, sizeof(key), &val, sizeof(val), 0);
	if (!ASSERT_OK(err, "add denied cgroup"))
		goto cleanup;

	/*
	 * Forked children must use join_parent_cgroup() because the
	 * cgroup workdir was created under the parent's PID and
	 * join_cgroup() constructs paths using getpid().
	 */

	/* Child migrating to /allowed should succeed */
	child = fork();
	if (!ASSERT_GE(child, 0, "fork child allowed"))
		goto cleanup;
	if (child == 0) {
		if (join_parent_cgroup("/allowed"))
			_exit(1);
		_exit(0);
	}
	err = waitpid(child, &status, 0);
	ASSERT_GT(err, 0, "waitpid allowed");
	ASSERT_TRUE(WIFEXITED(status), "allowed child exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "allowed migration succeeds");

	/* Child migrating to /denied should fail */
	child = fork();
	if (!ASSERT_GE(child, 0, "fork child denied"))
		goto cleanup;
	if (child == 0) {
		if (join_parent_cgroup("/denied") == 0)
			_exit(1); /* Should have failed */
		if (errno != EPERM)
			_exit(2); /* Wrong errno */
		_exit(0);
	}
	err = waitpid(child, &status, 0);
	ASSERT_GT(err, 0, "waitpid denied");
	ASSERT_TRUE(WIFEXITED(status), "denied child exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "denied migration blocked");

	/* Detach BPF — /denied should now be accessible */
	test_cgroup_attach__detach(skel);

	child = fork();
	if (!ASSERT_GE(child, 0, "fork child post-detach"))
		goto cleanup;
	if (child == 0) {
		if (join_parent_cgroup("/denied"))
			_exit(1);
		_exit(0);
	}
	err = waitpid(child, &status, 0);
	ASSERT_GT(err, 0, "waitpid post-detach");
	ASSERT_TRUE(WIFEXITED(status), "post-detach child exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "post-detach migration free");

cleanup:
	if (skel)
		test_cgroup_attach__destroy(skel);
	if (allowed_fd >= 0)
		close(allowed_fd);
	if (denied_fd >= 0)
		close(denied_fd);
	cleanup_cgroup_environment();
}

/*
 * Subtest: verify_hook_args
 *
 * Verify that the hook receives correct src_cgrp, dst_cgrp, task pid,
 * and threadgroup values.
 */
static void test_verify_hook_args(void)
{
	struct test_cgroup_attach *skel = NULL;
	struct attach_event evt = {};
	unsigned long long src_cgid, dst_cgid;
	int src_fd = -1, dst_fd = -1;
	__u32 map_key = 0;
	char pid_str[32];
	int err;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_env"))
		return;

	src_fd = create_and_get_cgroup("/src");
	if (!ASSERT_GE(src_fd, 0, "create /src"))
		goto cleanup;

	dst_fd = create_and_get_cgroup("/dst");
	if (!ASSERT_GE(dst_fd, 0, "create /dst"))
		goto cleanup;

	/* Move ourselves to /src first */
	if (!ASSERT_OK(join_cgroup("/src"), "join /src"))
		goto cleanup;

	skel = test_cgroup_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto cleanup;

	err = test_cgroup_attach__attach(skel);
	if (!ASSERT_OK(err, "skel attach"))
		goto cleanup;

	skel->bss->monitored_pid = getpid();

	src_cgid = get_cgroup_id("/src");
	dst_cgid = get_cgroup_id("/dst");
	if (!ASSERT_NEQ(src_cgid, 0ULL, "get src cgroup id"))
		goto cleanup;
	if (!ASSERT_NEQ(dst_cgid, 0ULL, "get dst cgroup id"))
		goto cleanup;

	/* Migrate self to /dst via cgroup.procs (threadgroup=true) */
	snprintf(pid_str, sizeof(pid_str), "%d", getpid());
	if (!ASSERT_OK(write_cgroup_file("/dst", "cgroup.procs", pid_str),
		       "migrate to /dst"))
		goto cleanup;

	/* Read the recorded event */
	err = bpf_map__lookup_elem(skel->maps.last_event,
				   &map_key, sizeof(map_key),
				   &evt, sizeof(evt), 0);
	if (!ASSERT_OK(err, "read last_event"))
		goto cleanup;

	ASSERT_EQ(evt.src_cgrp_id, src_cgid, "src_cgrp_id matches");
	ASSERT_EQ(evt.dst_cgrp_id, dst_cgid, "dst_cgrp_id matches");
	ASSERT_EQ(evt.task_pid, (__u32)getpid(), "task_pid matches");
	ASSERT_EQ(evt.threadgroup, 1, "threadgroup is true for cgroup.procs");
	ASSERT_GE(evt.hook_count, (__u32)1, "hook fired at least once");

cleanup:
	if (skel)
		test_cgroup_attach__destroy(skel);
	if (src_fd >= 0)
		close(src_fd);
	if (dst_fd >= 0)
		close(dst_fd);
	cleanup_cgroup_environment();
}

/*
 * Subtest: clone_into_cgroup
 *
 * Verify the hook fires on the clone3(CLONE_INTO_CGROUP) path and can
 * deny spawning a child directly into a cgroup.
 */
static void test_clone_into_cgroup(void)
{
	struct test_cgroup_attach *skel = NULL;
	int allowed_fd = -1, denied_fd = -1;
	unsigned long long denied_cgid, allowed_cgid;
	struct attach_event evt = {};
	__u32 map_key = 0;
	__u64 key;
	__u8 val = 1;
	int err, status;
	pid_t child;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_env"))
		return;

	allowed_fd = create_and_get_cgroup("/clone_allowed");
	if (!ASSERT_GE(allowed_fd, 0, "create /clone_allowed"))
		goto cleanup;

	denied_fd = create_and_get_cgroup("/clone_denied");
	if (!ASSERT_GE(denied_fd, 0, "create /clone_denied"))
		goto cleanup;

	skel = test_cgroup_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto cleanup;

	err = test_cgroup_attach__attach(skel);
	if (!ASSERT_OK(err, "skel attach"))
		goto cleanup;

	skel->bss->monitored_pid = getpid();

	denied_cgid = get_cgroup_id("/clone_denied");
	allowed_cgid = get_cgroup_id("/clone_allowed");
	if (!ASSERT_NEQ(denied_cgid, 0ULL, "get denied cgroup id"))
		goto cleanup;
	if (!ASSERT_NEQ(allowed_cgid, 0ULL, "get allowed cgroup id"))
		goto cleanup;

	key = denied_cgid;
	err = bpf_map__update_elem(skel->maps.denied_cgroups,
				   &key, sizeof(key), &val, sizeof(val), 0);
	if (!ASSERT_OK(err, "add denied cgroup"))
		goto cleanup;

	/* clone3 into denied cgroup should fail */
	child = do_clone3(denied_fd);
	if (child >= 0) {
		waitpid(child, NULL, 0);
		ASSERT_LT(child, 0, "clone3 into denied should fail");
		goto cleanup;
	}
	if (errno == ENOSYS || errno == E2BIG) {
		test__skip();
		goto cleanup;
	}
	ASSERT_EQ(errno, EPERM, "clone3 denied errno");

	/* clone3 into allowed cgroup should succeed */
	child = do_clone3(allowed_fd);
	if (!ASSERT_GE(child, 0, "clone3 into allowed"))
		goto cleanup;
	if (child == 0)
		_exit(0);

	err = waitpid(child, &status, 0);
	ASSERT_GT(err, 0, "waitpid clone3 allowed");
	ASSERT_TRUE(WIFEXITED(status), "clone3 child exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "clone3 child ok");

	/* Verify the hook recorded the allowed clone */
	err = bpf_map__lookup_elem(skel->maps.last_event,
				   &map_key, sizeof(map_key),
				   &evt, sizeof(evt), 0);
	if (!ASSERT_OK(err, "read last_event"))
		goto cleanup;

	ASSERT_EQ(evt.dst_cgrp_id, allowed_cgid, "clone3 dst_cgrp_id");

cleanup:
	if (skel)
		test_cgroup_attach__destroy(skel);
	if (allowed_fd >= 0)
		close(allowed_fd);
	if (denied_fd >= 0)
		close(denied_fd);
	cleanup_cgroup_environment();
}

void test_cgroup_attach(void)
{
	if (test__start_subtest("deny_migration"))
		test_deny_migration();
	if (test__start_subtest("verify_hook_args"))
		test_verify_hook_args();
	if (test__start_subtest("clone_into_cgroup"))
		test_clone_into_cgroup();
}
