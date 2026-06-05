// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <errno.h>
#include <sys/mman.h>

/* Make sure an arena mapping cannot be split by a partial munmap(). */

#define NR_PAGES 3

void test_arena_split(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	long ps = sysconf(_SC_PAGESIZE);
	size_t sz = (size_t)NR_PAGES * ps;
	void *area;
	int fd, ret, err;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_split", 0, 0, NR_PAGES, &opts);
	if (!ASSERT_OK_FD(fd, "arena map create"))
		return;

	area = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(area, MAP_FAILED, "mmap arena"))
		goto close_fd;

	ret = munmap((char *)area + ps, ps);
	err = errno;
	if (ASSERT_ERR(ret, "split munmap"))
		ASSERT_EQ(err, EINVAL, "split munmap errno");

	munmap(area, sz);
close_fd:
	close(fd);
}
