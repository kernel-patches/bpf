// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <test_progs.h>

#include "strncmp_helper.skel.h"

static void run_strncmp_bench(struct strncmp_helper *skel, const char *name,
			      int fd, int loop)
{
	struct timespec begin, end;
	struct stat stat;
	double nsecs;
	int i;

	skel->bss->equal = 0;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	for (i = 0; i < loop; i++)
		fstat(fd, &stat);
	clock_gettime(CLOCK_MONOTONIC, &end);

	nsecs = (end.tv_sec - begin.tv_sec) * 1e9 + (end.tv_nsec - begin.tv_nsec);
	fprintf(stdout, "%s: loop %d nsecs %.0f\n", name, loop, nsecs);
	fprintf(stdout, "equal nr %u\n", skel->bss->equal);
}

void test_test_strncmp_helper(void)
{
	const char *fpath = "/tmp/1234123412341234123412341234123412341234";
	struct strncmp_helper *skel;
	struct bpf_link *link;
	int fd, loop;

	skel = strncmp_helper__open_and_load();
	if (!ASSERT_OK_PTR(skel, "helper load"))
		return;

	fd = open(fpath, O_CREAT | O_RDONLY, 0644);
	if (!ASSERT_GE(fd, 0, "create file"))
		goto close_prog;

	loop = 5000;
	skel->bss->pid = getpid();

	link = bpf_program__attach(skel->progs.vfs_getattr_nocmp);
	if (!ASSERT_EQ(libbpf_get_error(link), 0, "attach nocmp"))
		goto clean_file;

	run_strncmp_bench(skel, "nocmp", fd, loop);
	bpf_link__destroy(link);

	link = bpf_program__attach(skel->progs.vfs_getattr_cmp);
	if (!ASSERT_EQ(libbpf_get_error(link), 0, "attach cmp"))
		goto clean_file;

	run_strncmp_bench(skel, "cmp", fd, loop);
	bpf_link__destroy(link);

	link = bpf_program__attach(skel->progs.vfs_getattr_cmp_v2);
	if (!ASSERT_EQ(libbpf_get_error(link), 0, "attach cmp_v2"))
		goto clean_file;

	run_strncmp_bench(skel, "cmp_v2", fd, loop);
	bpf_link__destroy(link);

clean_file:
	close(fd);
	unlink(fpath);
close_prog:
	strncmp_helper__destroy(skel);
}
