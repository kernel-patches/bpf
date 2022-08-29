// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/types.h>
#include <test_progs.h>
#include "task_local_storage.skel.h"
#include "task_local_storage_exit_creds.skel.h"
#include "task_ls_recursion.skel.h"

struct lookup_ctx {
	bool start;
	bool stop;
	int pid_fd;
	int map_fd;
	int loop;
};

static void test_sys_enter_exit(void)
{
	struct task_local_storage *skel;
	int err;

	skel = task_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->target_pid = syscall(SYS_gettid);

	err = task_local_storage__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	syscall(SYS_gettid);
	syscall(SYS_gettid);

	/* 3x syscalls: 1x attach and 2x gettid */
	ASSERT_EQ(skel->bss->enter_cnt, 3, "enter_cnt");
	ASSERT_EQ(skel->bss->exit_cnt, 3, "exit_cnt");
	ASSERT_EQ(skel->bss->mismatch_cnt, 0, "mismatch_cnt");
out:
	task_local_storage__destroy(skel);
}

static void test_exit_creds(void)
{
	struct task_local_storage_exit_creds *skel;
	int err;

	skel = task_local_storage_exit_creds__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = task_local_storage_exit_creds__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* trigger at least one exit_creds() */
	if (CHECK_FAIL(system("ls > /dev/null")))
		goto out;

	/* sync rcu to make sure exit_creds() is called for "ls" */
	kern_sync_rcu();
	ASSERT_EQ(skel->bss->valid_ptr_count, 0, "valid_ptr_count");
	ASSERT_NEQ(skel->bss->null_ptr_count, 0, "null_ptr_count");
out:
	task_local_storage_exit_creds__destroy(skel);
}

static void test_recursion(void)
{
	struct task_ls_recursion *skel;
	int err;

	skel = task_ls_recursion__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = task_ls_recursion__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* trigger sys_enter, make sure it does not cause deadlock */
	syscall(SYS_gettid);

out:
	task_ls_recursion__destroy(skel);
}

static void *lookup_fn(void *arg)
{
	struct lookup_ctx *ctx = arg;
	long value;
	int i = 0;

	while (!ctx->start)
		usleep(1);

	while (!ctx->stop && i++ < ctx->loop)
		bpf_map_lookup_elem(ctx->map_fd, &ctx->pid_fd, &value);
	return NULL;
}

static void test_preemption(void)
{
	struct task_local_storage *skel;
	struct lookup_ctx ctx;
	unsigned int i, nr;
	cpu_set_t old, new;
	pthread_t *tids;
	int err;

	skel = task_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/* Save the old affinity setting */
	sched_getaffinity(getpid(), sizeof(old), &old);

	/* Pinned on CPU 0 */
	CPU_ZERO(&new);
	CPU_SET(0, &new);
	sched_setaffinity(getpid(), sizeof(new), &new);

	nr = 256;
	tids = calloc(nr, sizeof(*tids));
	if (!ASSERT_NEQ(tids, NULL, "no mem"))
		goto out;

	ctx.start = false;
	ctx.stop = false;
	ctx.pid_fd = sys_pidfd_open(getpid(), 0);
	ctx.map_fd = bpf_map__fd(skel->maps.enter_id);
	ctx.loop = 8192;
	for (i = 0; i < nr; i++) {
		err = pthread_create(&tids[i], NULL, lookup_fn, &ctx);
		if (err) {
			unsigned int j;

			ASSERT_OK(err, "pthread_create");

			ctx.stop = true;
			ctx.start = true;
			for (j = 0; j < i; j++)
				pthread_join(tids[j], NULL);
			goto out;
		}
	}

	ctx.start = true;
	for (i = 0; i < nr; i++)
		pthread_join(tids[i], NULL);

	err = task_local_storage__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	skel->bss->target_pid = syscall(SYS_gettid);
	syscall(SYS_gettid);

	/* If bpf_task_storage_trylock() fails, enter_cnt will be 0 */
	ASSERT_EQ(skel->bss->enter_cnt, 1, "enter_cnt");
out:
	free(tids);
	task_local_storage__destroy(skel);
	/* Restore affinity setting */
	sched_setaffinity(getpid(), sizeof(old), &old);
}

void test_task_local_storage(void)
{
	if (test__start_subtest("sys_enter_exit"))
		test_sys_enter_exit();
	if (test__start_subtest("exit_creds"))
		test_exit_creds();
	if (test__start_subtest("recursion"))
		test_recursion();
	if (test__start_subtest("preemption"))
		test_preemption();
}
