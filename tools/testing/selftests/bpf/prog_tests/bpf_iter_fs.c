// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <test_progs.h>
#include "bpf_iter_fs.skel.h"

static void test_bpf_iter_raw_inode(void)
{
	const char *fpath = "/tmp/raw_inode.test";
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	int ino_fd, iter_fd, err;
	struct bpf_iter_fs *skel;
	struct bpf_link *link;
	char buf[8192];
	ssize_t nr;

	ino_fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (!ASSERT_GE(ino_fd, 0, "open file"))
		return;
	ftruncate(ino_fd, 4095);

	skel = bpf_iter_fs__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto close_ino;

	bpf_program__set_autoload(skel->progs.dump_raw_inode, true);

	err = bpf_iter_fs__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto free_skel;

	memset(&linfo, 0, sizeof(linfo));
	linfo.fs.type = BPF_FS_ITER_INODE;
	linfo.fs.fd = ino_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_raw_inode, &opts);
	if (!ASSERT_OK_PTR(link, "attach iter"))
		goto free_skel;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create iter"))
		goto free_link;

	nr = read(iter_fd, buf, sizeof(buf));
	if (!ASSERT_GT(nr, 0, "read iter"))
		goto close_iter;

	buf[nr - 1] = 0;
	puts(buf);

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
free_skel:
	bpf_iter_fs__destroy(skel);
close_ino:
	close(ino_fd);
}

static void test_bpf_iter_inode(void)
{
	const char *fpath = "/tmp/inode.test";
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	int ino_fd, iter_fd, err;
	struct bpf_iter_fs *skel;
	struct bpf_link *link;
	char buf[8192];
	ssize_t nr;

	/* Close fd after reading iterator completes */
	ino_fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (!ASSERT_GE(ino_fd, 0, "open file"))
		return;
	pwrite(ino_fd, buf, sizeof(buf), 0);
	pwrite(ino_fd, buf, sizeof(buf), sizeof(buf) * 2);

	skel = bpf_iter_fs__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto close_ino;

	bpf_program__set_autoload(skel->progs.dump_inode, true);

	err = bpf_iter_fs__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto free_skel;

	memset(&linfo, 0, sizeof(linfo));
	linfo.fs.type = BPF_FS_ITER_INODE;
	linfo.fs.fd = ino_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_inode, &opts);
	if (!ASSERT_OK_PTR(link, "attach iter"))
		goto free_skel;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create iter"))
		goto free_link;

	nr = read(iter_fd, buf, sizeof(buf));
	if (!ASSERT_GT(nr, 0, "read iter"))
		goto close_iter;

	buf[nr - 1] = 0;
	puts(buf);

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
free_skel:
	bpf_iter_fs__destroy(skel);
close_ino:
	close(ino_fd);
}

static void test_bpf_iter_mnt(void)
{
	const char *fpath = "/tmp/mnt.test";
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	int mnt_fd, iter_fd, err;
	struct bpf_iter_fs *skel;
	struct bpf_link *link;
	char buf[8192];
	ssize_t nr;

	/* Close fd after reading iterator completes */
	mnt_fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (!ASSERT_GE(mnt_fd, 0, "open file"))
		return;

	skel = bpf_iter_fs__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto close_ino;

	bpf_program__set_autoload(skel->progs.dump_mnt, true);

	err = bpf_iter_fs__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto free_skel;

	memset(&linfo, 0, sizeof(linfo));
	linfo.fs.type = BPF_FS_ITER_MNT;
	linfo.fs.fd = mnt_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_mnt, &opts);
	if (!ASSERT_OK_PTR(link, "attach iter"))
		goto free_skel;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create iter"))
		goto free_link;

	nr = read(iter_fd, buf, sizeof(buf));
	if (!ASSERT_GT(nr, 0, "read iter"))
		goto close_iter;

	buf[nr - 1] = 0;
	puts(buf);

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
free_skel:
	bpf_iter_fs__destroy(skel);
close_ino:
	close(mnt_fd);
}

void test_bpf_iter_fs(void)
{
	if (test__start_subtest("dump_raw_inode"))
		test_bpf_iter_raw_inode();
	if (test__start_subtest("dump_inode"))
		test_bpf_iter_inode();
	if (test__start_subtest("dump_mnt"))
		test_bpf_iter_mnt();
}
