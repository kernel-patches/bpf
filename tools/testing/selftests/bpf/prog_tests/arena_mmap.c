// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/mman.h>
#include "arena_mmap_alloc.skel.h"

#define ARENA_PAGES 8

/* err == 0: the range ends above TASK_SIZE. EINVAL or ENOMEM, this depends on the arch */
static void test_refused(__u64 map_extra, __u64 addr, int pages, int flags, int err)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_MMAPABLE,
		    .map_extra = map_extra);
	void *area;
	int fd;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, ARENA_PAGES, &opts);
	if (fd == -EOPNOTSUPP) {
		test__skip();
		return;
	}
	/* No task can map this range, so the kernel can also refuse the map. */
	if (fd < 0 && map_extra)
		return;
	if (!ASSERT_GE(fd, 0, "bpf_map_create"))
		return;

	area = mmap((void *)(unsigned long)addr, pages * getpagesize(),
		    PROT_READ | PROT_WRITE, MAP_SHARED | flags, fd, 0);
	if (!ASSERT_EQ(area, MAP_FAILED, "mmap"))
		munmap(area, pages * getpagesize());
	else if (err || errno != ENOMEM)
		ASSERT_EQ(errno, err ?: EINVAL, "errno");
	close(fd);
}

static void test_short_mmap_alloc(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts, .map_flags = BPF_F_MMAPABLE);
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	struct arena_mmap_alloc *skel = NULL;
	size_t size = 4 * getpagesize();
	void *area;
	int fd, err;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0,
			    ARENA_PAGES, &map_opts);
	if (fd == -EOPNOTSUPP) {
		test__skip();
		return;
	}
	if (!ASSERT_GE(fd, 0, "bpf_map_create"))
		return;

	/* The short mapping must be the first mmap() of this arena. */
	area = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(area, MAP_FAILED, "short_mmap"))
		goto out_close;

	/* Reuse the map so libbpf does not mmap all ARENA_PAGES on load. */
	skel = arena_mmap_alloc__open();
	if (!ASSERT_OK_PTR(skel, "arena_mmap_alloc__open"))
		goto out_unmap;
	err = bpf_map__reuse_fd(skel->maps.arena, fd);
	if (!ASSERT_OK(err, "reuse_arena_fd"))
		goto out_destroy;
	err = arena_mmap_alloc__load(skel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto out_destroy;
	}
	if (!ASSERT_OK(err, "arena_mmap_alloc__load"))
		goto out_destroy;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.alloc_beyond_vma),
				     &run_opts);
	if (ASSERT_OK(err, "alloc_beyond_vma"))
		ASSERT_OK(run_opts.retval, "alloc_beyond_vma_retval");

out_destroy:
	arena_mmap_alloc__destroy(skel);
out_unmap:
	munmap(area, size);
out_close:
	close(fd);
}

void serial_test_arena_mmap(void)
{
	__u64 page = getpagesize(), last = -(ARENA_PAGES * page);

	if (test__start_subtest("long"))
		test_refused(0, 0, ARENA_PAGES + 1, 0, E2BIG);
	if (test__start_subtest("address_0"))
		test_refused(0, 0, ARENA_PAGES, MAP_FIXED, EINVAL);
	if (test__start_subtest("crosses_4g"))
		test_refused(0, (1ULL << 32) - page, ARENA_PAGES, MAP_FIXED, EINVAL);
	if (test__start_subtest("crosses_4g_noreplace"))
		test_refused(0, (1ULL << 32) - page, ARENA_PAGES, MAP_FIXED_NOREPLACE, EINVAL);
	if (test__start_subtest("wraps"))
		test_refused(0, -page, ARENA_PAGES, MAP_FIXED, 0);
	if (test__start_subtest("map_extra_last_pages"))
		test_refused(last, last, ARENA_PAGES, MAP_FIXED, 0);
	if (test__start_subtest("short_mmap_alloc"))
		test_short_mmap_alloc();
}
