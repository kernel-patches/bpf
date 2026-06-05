// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>

/* Make sure an arena mapping is not inherited across fork(). */

#define NR_PAGES 3

void test_arena_fork(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	long ps = sysconf(_SC_PAGESIZE);
	size_t sz = (size_t)NR_PAGES * ps;
	void *area;
	int fd, ret, status;
	pid_t pid;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_fork", 0, 0, NR_PAGES, &opts);
	if (!ASSERT_OK_FD(fd, "arena map create"))
		return;

	area = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(area, MAP_FAILED, "mmap arena"))
		goto close_fd;

	pid = fork();
	if (pid == 0) {
		unsigned char vec;
		int rc;

		/* If the mapping was not inherited the range is unmapped in
		 * the child, so mincore() fails with ENOMEM. A success means
		 * the child wrongly inherited the mapping.
		 */
		rc = mincore(area, ps, &vec);
		if (rc == 0)
			_exit(1);
		_exit(errno == ENOMEM ? 0 : 2);
	}
	if (ASSERT_GE(pid, 0, "fork")) {
		while ((ret = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
			;
		if (ASSERT_EQ(ret, pid, "waitpid"))
			ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
				    "child must not inherit arena mapping");
	}

	munmap(area, sz);
close_fd:
	close(fd);
}
