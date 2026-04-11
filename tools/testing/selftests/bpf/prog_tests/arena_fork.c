// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

/*
 * Test that forking a process with an arena mmap does not cause a
 * use-after-free when the parent unmaps and the child frees arena pages.
 *
 * The bug: arena_vm_open() only incremented a refcount but never registered
 * the child's VMA. After parent munmap, vml->vma pointed to a freed
 * vm_area_struct. bpf_arena_free_pages -> zap_pages would then UAF.
 */
#include <test_progs.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#ifndef PAGE_SIZE
#define PAGE_SIZE getpagesize()
#endif

#include "arena_fork.skel.h"

void test_arena_fork(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	struct arena_fork *skel;
	size_t arena_sz;
	void *arena_addr;
	int arena_fd, ret, status;
	pid_t pid;

	skel = arena_fork__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	arena_fd = bpf_map__fd(skel->maps.arena);

	/* libbpf mmaps the arena via initial_value */
	arena_addr = bpf_map__initial_value(skel->maps.arena, &arena_sz);
	if (!ASSERT_OK_PTR(arena_addr, "arena_mmap"))
		goto out;

	/* Get real arena byte size for munmap */
	bpf_map_get_info_by_fd(arena_fd, &info, &info_len);
	arena_sz = (size_t)info.max_entries * PAGE_SIZE;

	/* Allocate 4 pages in the arena via BPF */
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_alloc),
				     &opts);
	if (!ASSERT_OK(ret, "alloc_run") ||
	    !ASSERT_OK(opts.retval, "alloc_ret"))
		goto out;

	/* Fault in a page so zap_pages has work to do */
	((char *)arena_addr)[0] = 'A';

	/* Fork: child inherits the arena VMA */
	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;

	if (pid == 0) {
		/* Child: parent will unmap first, then we free pages.
		 * Without the fix, this triggers UAF in zap_pages.
		 */
		LIBBPF_OPTS(bpf_test_run_opts, child_opts);
		int free_fd = bpf_program__fd(skel->progs.arena_free);

		usleep(200000); /* let parent munmap first */

		ret = bpf_prog_test_run_opts(free_fd, &child_opts);
		_exit(ret || child_opts.retval);
	}

	/* Parent: unmap the arena, making vml->vma stale */
	munmap(arena_addr, arena_sz);

	/* Wait for child -- if kernel UAFs, child will crash/hang */
	waitpid(pid, &status, 0);
	ASSERT_TRUE(WIFEXITED(status), "child_exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child_exit_code");
out:
	arena_fork__destroy(skel);
}
