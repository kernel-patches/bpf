// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>

#include "bpffs_xattr_label.skel.h"

/*
 * Exercises the bpffs xattr support together with a BPF LSM example:
 *
 *   1. pin a BPF map and create a directory in bpffs,
 *   2. attach the labels (security.bpf.foo) with XATTR_CREATE,
 *   3. confirm the kernel (BPF LSM) reads back exactly what userspace set,
 *   4. confirm the label cannot be changed/removed and the pin cannot be
 *      unlinked/rmdir'd/renamed while labeled,
 *   5. confirm an unlabeled pin is unaffected (control).
 */

static const char value_foo[] = "0123456789abcdef0123456789abcdef";
static const char xattr_foo[] = "security.bpf.foo";

void test_bpffs_xattr_label(void)
{
	char map_path[128], labeled_dir[128], plain_dir[128], rename_to[128];
	char dir[] = "/tmp/bpffs_xattr_label.XXXXXX";
	struct bpffs_xattr_label *skel = NULL;
	bool mounted = false;
	int map_fd = -1, err;
	char out[64];

	if (!ASSERT_OK_PTR(mkdtemp(dir), "mkdtemp"))
		return;

	err = mount("bpf", dir, "bpf", 0, NULL);
	if (!ASSERT_OK(err, "mount_bpffs"))
		goto out;
	mounted = true;

	snprintf(map_path, sizeof(map_path), "%s/themap", dir);
	snprintf(labeled_dir, sizeof(labeled_dir), "%s/labeled", dir);
	snprintf(plain_dir, sizeof(plain_dir), "%s/plain", dir);
	snprintf(rename_to, sizeof(rename_to), "%s/renamed", dir);

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "label_map", 4, 4, 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, map_path), "map_pin"))
		goto out;
	if (!ASSERT_OK(mkdir(labeled_dir, 0755), "mkdir_labeled"))
		goto out;
	if (!ASSERT_OK(mkdir(plain_dir, 0755), "mkdir_plain"))
		goto out;

	skel = bpffs_xattr_label__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(bpffs_xattr_label__attach(skel), "skel_attach"))
		goto out;

	err = setxattr(map_path, xattr_foo, value_foo, sizeof(value_foo),
		       XATTR_CREATE);
	if (!ASSERT_OK(err, "setxattr_map_create"))
		goto out;
	ASSERT_OK(setxattr(labeled_dir, xattr_foo, value_foo, sizeof(value_foo),
			   XATTR_CREATE), "setxattr_dir_create");

	err = getxattr(map_path, xattr_foo, out, sizeof(out));
	ASSERT_EQ(err, sizeof(value_foo), "getxattr_len");
	ASSERT_MEMEQ(out, value_foo, sizeof(value_foo), "getxattr_value");

	ASSERT_EQ(skel->bss->read_value_len, sizeof(value_foo), "bpf_read_len");
	ASSERT_MEMEQ(skel->bss->read_value, value_foo, sizeof(value_foo),
		     "bpf_read_value");

	err = setxattr(map_path, xattr_foo, "changed", sizeof("changed"), 0);
	ASSERT_EQ(err, -1, "setxattr_replace_ret");
	ASSERT_EQ(errno, EPERM, "setxattr_replace_errno");

	ASSERT_EQ(removexattr(map_path, xattr_foo), -1, "removexattr_ret");
	ASSERT_EQ(errno, EPERM, "removexattr_errno");

	ASSERT_EQ(unlink(map_path), -1, "unlink_labeled_ret");
	ASSERT_EQ(errno, EPERM, "unlink_labeled_errno");
	ASSERT_EQ(rename(map_path, rename_to), -1, "rename_labeled_ret");
	ASSERT_EQ(errno, EPERM, "rename_labeled_errno");

	ASSERT_EQ(rmdir(labeled_dir), -1, "rmdir_labeled_ret");
	ASSERT_EQ(errno, EPERM, "rmdir_labeled_errno");

	ASSERT_OK(rmdir(plain_dir), "rmdir_plain");

	err = getxattr(map_path, xattr_foo, out, sizeof(out));
	ASSERT_EQ(err, sizeof(value_foo), "getxattr_len_after");
	ASSERT_MEMEQ(out, value_foo, sizeof(value_foo), "getxattr_value_after");

out:
	bpffs_xattr_label__destroy(skel);
	if (map_fd >= 0)
		close(map_fd);
	if (mounted) {
		unlink(map_path);
		rmdir(labeled_dir);
		rmdir(plain_dir);
		umount(dir);
	}
	rmdir(dir);
}
