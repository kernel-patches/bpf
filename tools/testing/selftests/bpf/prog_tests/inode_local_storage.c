// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <stdio.h>
#include <sys/stat.h>
#include <test_progs.h>
#include "inode_storage_recursion.skel.h"

#define TDIR "/tmp/inode_local_storage"
#define TDIR_PARENT "/tmp"

static void test_recursion(void)
{
	struct inode_storage_recursion *skel;
	struct bpf_prog_info info;
	__u32 info_len = sizeof(info);
	int err, prog_fd, map_fd, inode_fd = -1;
	long value;

	skel = inode_storage_recursion__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->test_pid = getpid();

	err = inode_storage_recursion__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	err = mkdir(TDIR, 0755);
	if (!ASSERT_OK(err, "mkdir " TDIR))
		goto out;

	inode_fd = open(TDIR_PARENT, O_RDONLY | O_CLOEXEC);
	if (!ASSERT_OK_FD(inode_fd, "open inode_fd"))
		goto out;

	/* Detach so that the following lookup won't trigger
	 * trace_inode_storage_lookup and further change the values.
	 */
	inode_storage_recursion__detach(skel);
	map_fd = bpf_map__fd(skel->maps.inode_map);
	err = bpf_map_lookup_elem(map_fd, &inode_fd, &value);
	ASSERT_OK(err, "lookup inode_map");

	/* Check trace_inode_mkdir for the reason that value == 201 */
	ASSERT_EQ(value, 201, "inode_map value");
	ASSERT_EQ(skel->bss->nr_del_errs, 1, "bpf_task_storage_delete busy");

	prog_fd = bpf_program__fd(skel->progs.trace_inode_mkdir);
	memset(&info, 0, sizeof(info));
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	ASSERT_OK(err, "get prog info");
	ASSERT_EQ(info.recursion_misses, 0, "trace_inode_mkdir prog recursion");

	prog_fd = bpf_program__fd(skel->progs.trace_inode_storage_lookup);
	memset(&info, 0, sizeof(info));
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	ASSERT_OK(err, "get prog info");
	ASSERT_EQ(info.recursion_misses, 3, "trace_inode_storage_lookup prog recursion");

out:
	rmdir(TDIR);
	close(inode_fd);
	inode_storage_recursion__destroy(skel);
}

void test_inode_localstorage(void)
{
	if (test__start_subtest("recursion"))
		test_recursion();
}
