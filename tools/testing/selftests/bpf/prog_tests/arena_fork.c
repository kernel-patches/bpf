// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>

/* Regression test for commit 4fddde2a732d ("bpf: Fix use-after-free in
 * arena_vm_close on fork"): an arena VMA must reject a splitting munmap()
 * (.may_split) and must not be inherited across fork() (VM_DONTCOPY). On
 * an unfixed kernel both operations succeed.
 */

#define NR_PAGES 3

void test_arena_fork(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	long ps = sysconf(_SC_PAGESIZE);
	size_t sz = (size_t)NR_PAGES * ps;
	int fd, ret, status, err;
	void *area;
	pid_t pid;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_fork", 0, 0, NR_PAGES, &opts);
	if (!ASSERT_OK_FD(fd, "arena map create"))
		return;

	area = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(area, MAP_FAILED, "mmap arena"))
		goto close_fd;

	/* A split of the arena VMA must be rejected (.may_split). */
	ret = munmap((char *)area + ps, ps);
	err = errno;
	ASSERT_ERR(ret, "split munmap rejected");
	ASSERT_EQ(err, EINVAL, "split munmap errno");

	/* The child of a fork() must not inherit the arena VMA (VM_DONTCOPY);
	 * mincore() returns ENOMEM for the unmapped range.
	 */
	pid = fork();
	if (ASSERT_GE(pid, 0, "fork")) {
		if (pid == 0) {
			unsigned char vec;

			_exit(mincore(area, ps, &vec) < 0 && errno == ENOMEM ? 0 : 1);
		}
		while ((ret = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
			;
		if (ASSERT_EQ(ret, pid, "waitpid"))
			ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
				    "child must not inherit arena vma");
	}

	munmap(area, sz);
close_fd:
	close(fd);
}
