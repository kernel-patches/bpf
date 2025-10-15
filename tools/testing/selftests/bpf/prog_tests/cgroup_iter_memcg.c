// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "cgroup_iter_memcg.h"
#include "cgroup_iter_memcg.skel.h"

int read_stats(struct bpf_link *link)
{
	int fd, ret = 0;
	ssize_t bytes;

	fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_OK_FD(fd, "bpf_iter_create"))
		return 1;

	/*
	 * Invoke iter program by reading from its fd. We're not expecting any
	 * data to be written by the bpf program so the result should be zero.
	 * Results will be read directly through the custom data section
	 * accessible through skel->data_query.memcg_query.
	 */
	bytes = read(fd, NULL, 0);
	if (!ASSERT_EQ(bytes, 0, "read fd"))
		ret = 1;

	close(fd);
	return ret;
}

static void test_anon(struct bpf_link *link,
		struct memcg_query *memcg_query)
{
	void *map;
	size_t len;
	long val;

	len = sysconf(_SC_PAGESIZE) * 1024;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		return;

	val = memcg_query->nr_anon_mapped;
	if (!ASSERT_GE(val, 0, "initial anon mapped val"))
		return;

	/*
	 * Increase memcg anon usage by mapping and writing
	 * to a new anon region.
	 */
	map = mmap(NULL, len, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!ASSERT_NEQ(map, MAP_FAILED, "mmap anon"))
		return;

	memset(map, 1, len);

	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup;

	ASSERT_GT(memcg_query->nr_anon_mapped, val, "final anon mapped val");

cleanup:
	munmap(map, len);
}

static void test_file(struct bpf_link *link,
		struct memcg_query *memcg_query)
{
	void *map;
	size_t len;
	long val_pages, val_mapped;
	FILE *f;
	int fd;

	len = sysconf(_SC_PAGESIZE) * 1024;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		return;

	val_pages = memcg_query->nr_file_pages;
	if (!ASSERT_GE(val_pages, 0, "initial file val"))
		return;
	val_mapped = memcg_query->nr_file_mapped;
	if (!ASSERT_GE(val_mapped, 0, "initial file mapped val"))
		return;

	/*
	 * Increase memcg file usage by creating and writing
	 * to a temoprary mapped file.
	 */
	f = tmpfile();
	if (!ASSERT_OK_PTR(f, "tmpfile"))
		return;
	fd = fileno(f);
	if (!ASSERT_OK_FD(fd, "open fd"))
		return;
	if (!ASSERT_OK(ftruncate(fd, len), "ftruncate"))
		goto cleanup_fd;

	map = mmap(NULL, len, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(map, MAP_FAILED, "mmap file"))
		goto cleanup_fd;

	memset(map, 1, len);

	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup_map;

	ASSERT_GT(memcg_query->nr_file_pages, val_pages, "final file value");
	ASSERT_GT(memcg_query->nr_file_mapped, val_mapped,
			"final file mapped value");

cleanup_map:
	munmap(map, len);
cleanup_fd:
	close(fd);
}

static void test_shmem(struct bpf_link *link,
		struct memcg_query *memcg_query)
{
	size_t len;
	int fd;
	void *map;
	long val;

	len = sysconf(_SC_PAGESIZE) * 1024;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		return;

	val = memcg_query->nr_shmem;
	if (!ASSERT_GE(val, 0, "init shmem val"))
		return;

	/*
	 * Increase memcg shmem usage by creating and writing
	 * to a shmem object.
	 */
	fd = shm_open("/tmp_shmem", O_CREAT | O_RDWR, 0644);
	if (!ASSERT_OK_FD(fd, "shm_open"))
		return;

	if (!ASSERT_OK(ftruncate(fd, len), "ftruncate"))
		goto cleanup_fd;

	map = mmap(NULL, len, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(map, MAP_FAILED, "mmap shmem"))
		goto cleanup_fd;

	memset(map, 1, len);

	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup_map;

	ASSERT_GT(memcg_query->nr_shmem, val, "final shmem value");

cleanup_map:
	munmap(map, len);
cleanup_fd:
	close(fd);
	shm_unlink("/tmp_shmem");
}

static void test_kmem(struct bpf_link *link,
		struct memcg_query *memcg_query)
{
	int fds[2];
	int err;
	ssize_t bytes;
	size_t len;
	char *buf;
	long val;

	len = sysconf(_SC_PAGESIZE) * 1024;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		return;

	val = memcg_query->memcg_kmem;
	if (!ASSERT_GE(val, 0, "initial kmem val"))
		return;

	err = pipe2(fds, O_NONBLOCK);
	if (!ASSERT_OK(err, "pipe"))
		return;

	buf = malloc(len);
	memset(buf, 1, len);
	bytes = write(fds[1], buf, len);
	if (!ASSERT_GT(bytes, 0, "write"))
		goto cleanup;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup;

	ASSERT_GT(memcg_query->memcg_kmem, val, "kmem value");

cleanup:
	free(buf);
	close(fds[0]);
	close(fds[1]);
}

static void test_pgfault(struct bpf_link *link,
		struct memcg_query *memcg_query)
{
	void *map;
	size_t len;
	long val;

	len = sysconf(_SC_PAGESIZE) * 1024;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		return;

	val = memcg_query->pgfault;
	if (!ASSERT_GE(val, 0, "initial pgfault val"))
		return;

	/* Create region to use for triggering a page fault. */
	map = mmap(NULL, len, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!ASSERT_NEQ(map, MAP_FAILED, "mmap anon"))
		return;

	/* Trigger page fault. */
	memset(map, 1, len);

	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup;

	ASSERT_GT(memcg_query->pgfault, val, "final pgfault val");

cleanup:
	munmap(map, len);
}

void test_cgroup_iter_memcg(void)
{
	char *cgroup_rel_path = "/cgroup_iter_memcg_test";
	struct cgroup_iter_memcg *skel;
	struct bpf_link *link;
	int cgroup_fd, err;

	cgroup_fd = cgroup_setup_and_join(cgroup_rel_path);
	if (!ASSERT_OK_FD(cgroup_fd, "cgroup_setup_and_join"))
		return;

	skel = cgroup_iter_memcg__open();
	if (!ASSERT_OK_PTR(skel, "cgroup_iter_memcg__open"))
		goto cleanup_cgroup_fd;

	err = cgroup_iter_memcg__load(skel);
	if (!ASSERT_OK(err, "cgroup_iter_memcg__load"))
		goto cleanup_skel;

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {
		.cgroup.cgroup_fd = cgroup_fd,
		.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY,
	};
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_memcg_query, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto cleanup_cgroup_fd;

	if (test__start_subtest("cgroup_iter_memcg__anon"))
		test_anon(link, &skel->data_query->memcg_query);
	if (test__start_subtest("cgroup_iter_memcg__shmem"))
		test_shmem(link, &skel->data_query->memcg_query);
	if (test__start_subtest("cgroup_iter_memcg__file"))
		test_file(link, &skel->data_query->memcg_query);
	if (test__start_subtest("cgroup_iter_memcg__kmem"))
		test_kmem(link, &skel->data_query->memcg_query);
	if (test__start_subtest("cgroup_iter_memcg__pgfault"))
		test_pgfault(link, &skel->data_query->memcg_query);

	bpf_link__destroy(link);
cleanup_skel:
	cgroup_iter_memcg__destroy(skel);
cleanup_cgroup_fd:
	close(cgroup_fd);
	cleanup_cgroup_environment();
}
