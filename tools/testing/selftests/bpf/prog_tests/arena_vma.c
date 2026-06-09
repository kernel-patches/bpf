// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>

/* Make sure arena mappings cannot be split or inherited. */

#define NR_PAGES 3

static int arena_mmap(int *fd, void **area, size_t *sz)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);

	*sz = (size_t)NR_PAGES * sysconf(_SC_PAGESIZE);

	*fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_vma", 0, 0, NR_PAGES, &opts);
	if (!ASSERT_OK_FD(*fd, "arena map create"))
		return -1;

	*area = mmap(NULL, *sz, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
	if (!ASSERT_NEQ(*area, MAP_FAILED, "mmap arena")) {
		close(*fd);
		return -1;
	}
	return 0;
}

/* A partial munmap that would split the arena mapping must be rejected. */
static void split_test(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	void *area;
	size_t sz;
	int fd, ret, err;

	if (arena_mmap(&fd, &area, &sz))
		return;

	ret = munmap((char *)area + ps, ps);
	err = errno;
	if (ASSERT_ERR(ret, "split munmap"))
		ASSERT_EQ(err, EINVAL, "split munmap errno");

	munmap(area, sz);
	close(fd);
}

/* A forked child must not inherit the arena mapping. */
static void fork_test(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	void *area;
	size_t sz;
	int fd, ret, status;
	pid_t pid;

	if (arena_mmap(&fd, &area, &sz))
		return;

	pid = fork();
	if (pid == 0) {
		unsigned char vec;
		int rc;

		/*
		 * If the mapping was not inherited the range is unmapped in
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
	close(fd);
}

void test_arena_vma(void)
{
	if (test__start_subtest("split"))
		split_test();
	if (test__start_subtest("fork"))
		fork_test();
}
