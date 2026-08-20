// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#define _GNU_SOURCE
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "cgroup_iter_io.h"
#include "cgroup_iter_io.skel.h"

#define IO_SIZE (4 * 1024 * 1024)

static int read_stats(struct bpf_link *link)
{
	int fd, ret = 0;
	ssize_t bytes;

	fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_OK_FD(fd, "bpf_iter_create"))
		return 1;

	/* Results land in skel->data_query; the read itself returns no data. */
	bytes = read(fd, NULL, 0);
	if (!ASSERT_EQ(bytes, 0, "read fd"))
		ret = 1;

	close(fd);
	return ret;
}

/* Set up a loop device for cgroup-charged I/O. */
static int loop_setup(char *loop_path, size_t sz, int *ctl_fd, int *loop_fd,
		      int *back_fd)
{
	char back_path[] = "/tmp/cgroup_iter_io.XXXXXX";
	int nr;

	*ctl_fd = *loop_fd = *back_fd = -1;

	*ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (*ctl_fd < 0)
		return -1;

	nr = ioctl(*ctl_fd, LOOP_CTL_GET_FREE);
	if (nr < 0)
		goto err;
	snprintf(loop_path, sz, "/dev/loop%d", nr);

	*back_fd = mkstemp(back_path);
	if (*back_fd < 0)
		goto err;
	unlink(back_path);
	if (ftruncate(*back_fd, (off_t)IO_SIZE * 4))
		goto err;

	*loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
	if (*loop_fd < 0)
		goto err;
	if (ioctl(*loop_fd, LOOP_SET_FD, *back_fd))
		goto err;

	return 0;
err:
	if (*loop_fd >= 0)
		close(*loop_fd);
	if (*back_fd >= 0)
		close(*back_fd);
	close(*ctl_fd);
	*ctl_fd = *loop_fd = *back_fd = -1;
	return -1;
}

static void loop_teardown(const char *loop_path, int ctl_fd, int loop_fd,
			  int back_fd)
{
	int nr = -1;

	if (loop_fd >= 0) {
		ioctl(loop_fd, LOOP_CLR_FD, 0);
		close(loop_fd);
	}
	if (back_fd >= 0)
		close(back_fd);
	if (ctl_fd >= 0) {
		if (sscanf(loop_path, "/dev/loop%d", &nr) == 1 && nr >= 0)
			ioctl(ctl_fd, LOOP_CTL_REMOVE, nr);
		close(ctl_fd);
	}
}

/* O_DIRECT keeps I/O charged to the current cgroup. */
static int do_direct_io(const char *loop_path)
{
	void *buf;
	int fd, ret = -1;

	fd = open(loop_path, O_RDWR | O_DIRECT | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (posix_memalign(&buf, 4096, IO_SIZE))
		goto out_fd;
	memset(buf, 0xab, IO_SIZE);

	if (pwrite(fd, buf, IO_SIZE, 0) != IO_SIZE)
		goto out_buf;
	fsync(fd);
	if (pread(fd, buf, IO_SIZE, 0) != IO_SIZE)
		goto out_buf;
	ret = 0;
out_buf:
	free(buf);
out_fd:
	close(fd);
	return ret;
}

/* Read @dev's io.stat counters. @dev uses kernel dev_t encoding. */
static int parse_io_stat(int cgroup_fd, __u64 dev, struct io_query *out)
{
	unsigned int want_maj = dev >> 20, want_min = dev & ((1U << 20) - 1);
	char buf[4096], *line, *saveptr;
	int fd, n, ret = -1;

	fd = openat(cgroup_fd, "io.stat", O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';

	for (line = strtok_r(buf, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		unsigned long long rb = 0, wb = 0, ri = 0, wi = 0, db = 0, di = 0;
		unsigned int maj, min;

		/* Only the device id is required; missing counters stay zero. */
		if (sscanf(line,
			   "%u:%u rbytes=%llu wbytes=%llu rios=%llu wios=%llu dbytes=%llu dios=%llu",
			   &maj, &min, &rb, &wb, &ri, &wi, &db, &di) < 2)
			continue;
		if (maj != want_maj || min != want_min)
			continue;

		out->rbytes = rb;
		out->wbytes = wb;
		out->rios = ri;
		out->wios = wi;
		out->dbytes = db;
		out->dios = di;
		ret = 0;
		break;
	}
	return ret;
}

void test_cgroup_iter_io(void)
{
	char *cgroup_rel_path = "/cgroup_iter_io_test";
	int ctl_fd = -1, loop_fd = -1, back_fd = -1;
	struct cgroup_iter_io *skel = NULL;
	struct bpf_link *link = NULL;
	char loop_path[64];
	struct io_query *q;
	int cgroup_fd;

	cgroup_fd = cgroup_setup_and_join(cgroup_rel_path);
	if (!ASSERT_OK_FD(cgroup_fd, "cgroup_setup_and_join"))
		return;

	if (loop_setup(loop_path, sizeof(loop_path), &ctl_fd, &loop_fd, &back_fd)) {
		test__skip();	/* needs root + CONFIG_BLK_DEV_LOOP */
		goto cleanup_cgroup_fd;
	}

	skel = cgroup_iter_io__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cgroup_iter_io__open_and_load"))
		goto cleanup_loop;

	/* Convert glibc st_rdev to kernel dev_t format. */
	{
		struct stat lst;

		if (!ASSERT_OK(fstat(loop_fd, &lst), "fstat loop"))
			goto cleanup_skel;
		skel->data_query->target_dev =
			((__u64)major(lst.st_rdev) << 20) | minor(lst.st_rdev);
	}

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {
		.cgroup.cgroup_fd = cgroup_fd,
		.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY,
	};
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_io_query, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto cleanup_skel;

	/* This process is in the test cgroup, so the loop I/O is charged here. */
	if (!ASSERT_OK(do_direct_io(loop_path), "do_direct_io"))
		goto cleanup_link;

	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup_link;

	q = &skel->data_query->io_query;
	if (test__start_subtest("cgroup_iter_io__write")) {
		ASSERT_GT(q->wbytes, 0, "wbytes");
		ASSERT_GT(q->wios, 0, "wios");
	}
	if (test__start_subtest("cgroup_iter_io__read")) {
		ASSERT_GT(q->rbytes, 0, "rbytes");
		ASSERT_GT(q->rios, 0, "rios");
	}
	if (test__start_subtest("cgroup_iter_io__dev"))
		ASSERT_GT(q->dev, 0, "dev");

	/* Compare with io.stat without I/O between the reads. */
	if (test__start_subtest("cgroup_iter_io__match")) {
		struct io_query filev = {};

		if (ASSERT_OK(read_stats(link), "read stats") &&
		    ASSERT_OK(parse_io_stat(cgroup_fd, q->dev, &filev),
			      "parse io.stat")) {
			ASSERT_EQ(q->rbytes, filev.rbytes, "rbytes");
			ASSERT_EQ(q->wbytes, filev.wbytes, "wbytes");
			ASSERT_EQ(q->rios, filev.rios, "rios");
			ASSERT_EQ(q->wios, filev.wios, "wios");
			ASSERT_EQ(q->dbytes, filev.dbytes, "dbytes");
			ASSERT_EQ(q->dios, filev.dios, "dios");
		}
	}

cleanup_link:
	bpf_link__destroy(link);
cleanup_skel:
	cgroup_iter_io__destroy(skel);
cleanup_loop:
	loop_teardown(loop_path, ctl_fd, loop_fd, back_fd);
cleanup_cgroup_fd:
	close(cgroup_fd);
	cleanup_cgroup_environment();
}
