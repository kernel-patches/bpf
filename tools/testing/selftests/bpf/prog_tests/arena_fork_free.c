// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * Validate arena VMA tracking across fork.
 *
 * When a process with an arena mmap forks, each VMA must be independently
 * tracked. This test verifies that freeing arena pages after the parent
 * munmaps does not access stale VMA pointers.
 *
 * Sequence:
 *   1. Load arena, allocate pages via BPF
 *   2. fork() — child inherits arena mmap
 *   3. Parent: munmap the arena
 *   4. Parent: free arena pages via BPF — zap_pages() must only touch
 *      live VMAs
 *
 * With KASAN enabled, any stale VMA access will be caught.
 */
#include <test_progs.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/user.h>
#ifndef PAGE_SIZE
#define PAGE_SIZE getpagesize()
#endif
#include "arena_fork_free.skel.h"

void test_arena_fork_free(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_fork_free *skel;
	int pipe_fds[2] = {-1, -1};
	size_t arena_sz;
	void *arena_area;
	pid_t child;
	int ret, status;
	char buf;

	skel = arena_fork_free__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/* Step 1: allocate arena pages via BPF */
	ret = bpf_prog_test_run_opts(
		bpf_program__fd(skel->progs.arena_alloc), &opts);
	if (!ASSERT_OK(ret, "alloc_run"))
		goto out;
	if (!ASSERT_OK(opts.retval, "alloc_retval"))
		goto out;
	if (skel->bss->skip) {
		printf("%s:SKIP:compiler doesn't support arena_cast\n",
		       __func__);
		test__skip();
		goto out;
	}

	arena_area = bpf_map__initial_value(skel->maps.arena, &arena_sz);
	if (!ASSERT_OK_PTR(arena_area, "arena_area"))
		goto out;
	arena_sz = bpf_map__max_entries(skel->maps.arena) * PAGE_SIZE;

	if (!ASSERT_OK(pipe(pipe_fds), "pipe"))
		goto out;

	/* Step 2: fork — child inherits arena mmap */
	child = fork();
	if (!ASSERT_GE(child, 0, "fork")) {
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		goto out;
	}

	if (child == 0) {
		/* Child: keep arena mmap alive, wait for parent to signal */
		close(pipe_fds[1]);
		read(pipe_fds[0], &buf, 1);
		close(pipe_fds[0]);
		_exit(0);
	}

	/* Parent continues */
	close(pipe_fds[0]);
	pipe_fds[0] = -1;

	/* Step 3: munmap the arena in the parent */
	ret = munmap(arena_area, arena_sz);
	if (!ASSERT_OK(ret, "munmap"))
		goto signal_child;

	/*
	 * Step 4: free arena pages via BPF.
	 *
	 * Wait for the RCU grace period so the parent's VMA slab memory
	 * is actually freed (VMA freeing is deferred via call_rcu).
	 * This ensures KASAN can detect any stale VMA dereference in
	 * zap_pages().
	 */
	usleep(200000);
	opts.retval = 0;
	ret = bpf_prog_test_run_opts(
		bpf_program__fd(skel->progs.arena_free), &opts);
	ASSERT_OK(ret, "free_run");
	ASSERT_OK(opts.retval, "free_retval");

signal_child:
	close(pipe_fds[1]);
	pipe_fds[1] = -1;
	waitpid(child, &status, 0);
	ASSERT_TRUE(WIFEXITED(status), "child_exited");

out:
	arena_fork_free__destroy(skel);
}
