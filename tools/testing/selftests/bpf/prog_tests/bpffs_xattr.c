// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>

#include "test_link_pinning.skel.h"

static const char val_a[] = "value-a";
static const char val_b[] = "value-b-different-length-than-a";

static int mount_bpffs(char dir[64])
{
	int err;

	strcpy(dir, "/tmp/bpffs_xattr.XXXXXX");
	if (!mkdtemp(dir))
		return -errno;
	err = mount("bpf", dir, "bpf", 0, NULL);
	if (err) {
		err = -errno;
		rmdir(dir);
	}
	return err;
}

static void umount_bpffs(const char *dir)
{
	umount(dir);
	rmdir(dir);
}

static bool list_contains(const char *list, ssize_t list_len, const char *name)
{
	const char *p = list;

	while (p < list + list_len) {
		if (!strcmp(p, name))
			return true;
		p += strlen(p) + 1;
	}
	return false;
}

static void test_prefixes(void)
{
	char dir[64], list[256], buf[64];
	ssize_t n;
	int err;

	if (!ASSERT_OK(mount_bpffs(dir), "mount"))
		return;

	if (!ASSERT_OK(setxattr(dir, "user.foo", val_a, sizeof(val_a),
				XATTR_CREATE), "set_user"))
		goto out;
	if (!ASSERT_OK(setxattr(dir, "trusted.bar", val_a, sizeof(val_a),
				XATTR_CREATE), "set_trusted"))
		goto out;
	if (!ASSERT_OK(setxattr(dir, "security.baz", val_a, sizeof(val_a),
				XATTR_CREATE), "set_security"))
		goto out;

	err = getxattr(dir, "user.foo", buf, sizeof(buf));
	ASSERT_EQ(err, sizeof(val_a), "get_user_len");
	ASSERT_MEMEQ(buf, val_a, sizeof(val_a), "get_user_val");

	err = getxattr(dir, "trusted.bar", buf, sizeof(buf));
	ASSERT_EQ(err, sizeof(val_a), "get_trusted_len");
	ASSERT_MEMEQ(buf, val_a, sizeof(val_a), "get_trusted_val");

	err = getxattr(dir, "security.baz", buf, sizeof(buf));
	ASSERT_EQ(err, sizeof(val_a), "get_security_len");
	ASSERT_MEMEQ(buf, val_a, sizeof(val_a), "get_security_val");

	n = listxattr(dir, list, sizeof(list));
	if (!ASSERT_GT(n, 0, "listxattr"))
		goto out;
	ASSERT_TRUE(list_contains(list, n, "user.foo"), "list_user");
	ASSERT_TRUE(list_contains(list, n, "trusted.bar"), "list_trusted");
	ASSERT_TRUE(list_contains(list, n, "security.baz"), "list_security");

	ASSERT_OK(removexattr(dir, "trusted.bar"), "remove_trusted");
	err = getxattr(dir, "trusted.bar", buf, sizeof(buf));
	ASSERT_EQ(err, -1, "get_after_remove");
	ASSERT_EQ(errno, ENODATA, "get_after_remove_errno");

	err = getxattr(dir, "user.foo", buf, sizeof(buf));
	ASSERT_EQ(err, sizeof(val_a), "user_survives_remove");
out:
	umount_bpffs(dir);
}

static void test_unsupported_prefix(void)
{
	char dir[64];
	int err;

	if (!ASSERT_OK(mount_bpffs(dir), "mount"))
		return;

	err = setxattr(dir, "bogus.foo", val_a, sizeof(val_a), XATTR_CREATE);
	ASSERT_EQ(err, -1, "set_bogus_ret");
	ASSERT_EQ(errno, EOPNOTSUPP, "set_bogus_errno");

	err = setxattr(dir, "system.posix_acl_default", val_a, sizeof(val_a),
		       XATTR_CREATE);
	ASSERT_EQ(err, -1, "set_system_ret");

	umount_bpffs(dir);
}

static void test_flags(void)
{
	char dir[64], buf[8];
	int err;

	if (!ASSERT_OK(mount_bpffs(dir), "mount"))
		return;

	err = setxattr(dir, "user.x", val_a, sizeof(val_a), XATTR_REPLACE);
	ASSERT_EQ(err, -1, "replace_missing_ret");
	ASSERT_EQ(errno, ENODATA, "replace_missing_errno");

	err = removexattr(dir, "user.x");
	ASSERT_EQ(err, -1, "remove_missing_ret");
	ASSERT_EQ(errno, ENODATA, "remove_missing_errno");

	ASSERT_OK(setxattr(dir, "user.empty", "", 0, XATTR_CREATE), "set_empty");
	err = getxattr(dir, "user.empty", buf, sizeof(buf));
	ASSERT_EQ(err, 0, "get_empty_len");

	ASSERT_OK(setxattr(dir, "user.x", val_a, sizeof(val_a), XATTR_CREATE),
		  "create_x");
	err = setxattr(dir, "user.x", val_b, sizeof(val_b), XATTR_CREATE);
	ASSERT_EQ(err, -1, "create_existing_ret");
	ASSERT_EQ(errno, EEXIST, "create_existing_errno");

	ASSERT_OK(setxattr(dir, "user.x", val_b, sizeof(val_b), XATTR_REPLACE),
		  "replace_existing");

	err = getxattr(dir, "user.x", buf, sizeof(buf));
	ASSERT_EQ(err, -1, "get_too_small_ret");
	ASSERT_EQ(errno, ERANGE, "get_too_small_errno");

	err = getxattr(dir, "user.x", NULL, 0);
	ASSERT_EQ(err, sizeof(val_b), "get_query_len");

	umount_bpffs(dir);
}

static void test_inode_types(void)
{
	char dir[64], child[128], map_path[128], prog_path[128];
	char link_path[128], sym_path[128];
	struct test_link_pinning *skel = NULL;
	int map_fd = -1, err;
	char list[128], buf[64];

	if (!ASSERT_OK(mount_bpffs(dir), "mount"))
		return;

	/* mount root inode */
	ASSERT_OK(setxattr(dir, "user.root", val_a, sizeof(val_a), XATTR_CREATE),
		  "root_set");
	err = getxattr(dir, "user.root", buf, sizeof(buf));
	ASSERT_EQ(err, sizeof(val_a), "root_get");
	ASSERT_GT(listxattr(dir, list, sizeof(list)), 0, "root_list");

	/* directory: confirm no inheritance from parent */
	snprintf(child, sizeof(child), "%s/d", dir);
	if (!ASSERT_OK(mkdir(child, 0755), "mkdir"))
		goto out;
	err = getxattr(child, "user.root", buf, sizeof(buf));
	ASSERT_EQ(err, -1, "no_inherit_ret");
	ASSERT_EQ(errno, ENODATA, "no_inherit_errno");
	ASSERT_OK(setxattr(child, "user.dir", val_a, sizeof(val_a), XATTR_CREATE),
		  "dir_set");
	ASSERT_GT(listxattr(child, list, sizeof(list)), 0, "dir_list");

	/* map pin */
	snprintf(map_path, sizeof(map_path), "%s/m", dir);
	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "x", 4, 4, 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, map_path), "map_pin"))
		goto out;
	ASSERT_OK(setxattr(map_path, "user.map", val_a, sizeof(val_a),
			   XATTR_CREATE), "map_set");
	ASSERT_GT(listxattr(map_path, list, sizeof(list)), 0, "map_list");

	/* prog pin + link pin via a noop raw_tp prog */
	skel = test_link_pinning__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		goto out;

	snprintf(prog_path, sizeof(prog_path), "%s/p", dir);
	if (!ASSERT_OK(bpf_obj_pin(bpf_program__fd(skel->progs.raw_tp_prog),
				   prog_path), "prog_pin"))
		goto out;
	ASSERT_OK(setxattr(prog_path, "user.prog", val_a, sizeof(val_a),
			   XATTR_CREATE), "prog_set");
	ASSERT_GT(listxattr(prog_path, list, sizeof(list)), 0, "prog_list");

	if (!ASSERT_OK(test_link_pinning__attach(skel), "skel_attach"))
		goto out;

	snprintf(link_path, sizeof(link_path), "%s/l", dir);
	if (!ASSERT_OK(bpf_obj_pin(bpf_link__fd(skel->links.raw_tp_prog),
				   link_path), "link_pin"))
		goto out;
	ASSERT_OK(setxattr(link_path, "user.link", val_a, sizeof(val_a),
			   XATTR_CREATE), "link_set");
	ASSERT_GT(listxattr(link_path, list, sizeof(list)), 0, "link_list");

	/* symlink: user.* is rejected by VFS on S_IFLNK; trusted.* works */
	snprintf(sym_path, sizeof(sym_path), "%s/s", dir);
	if (!ASSERT_OK(symlink("m", sym_path), "symlink_create"))
		goto out;
	ASSERT_OK(lsetxattr(sym_path, "trusted.sym", val_a, sizeof(val_a),
			    XATTR_CREATE), "sym_set");
	ASSERT_GT(llistxattr(sym_path, list, sizeof(list)), 0, "sym_list");
out:
	test_link_pinning__destroy(skel);
	if (map_fd >= 0)
		close(map_fd);
	umount_bpffs(dir);
}

static void test_repin_same_path(void)
{
	int map_a = -1, map_b = -1, err;
	char dir[64], path[128], buf[16];

	if (!ASSERT_OK(mount_bpffs(dir), "mount"))
		return;
	snprintf(path, sizeof(path), "%s/m", dir);

	map_a = bpf_map_create(BPF_MAP_TYPE_ARRAY, "a", 4, 4, 1, NULL);
	if (!ASSERT_GE(map_a, 0, "map_a"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_a, path), "pin_a"))
		goto out;
	ASSERT_OK(setxattr(path, "user.k", val_a, sizeof(val_a), XATTR_CREATE),
		  "set_a");
	if (!ASSERT_OK(unlink(path), "unlink_a"))
		goto out;

	map_b = bpf_map_create(BPF_MAP_TYPE_ARRAY, "b", 4, 4, 1, NULL);
	if (!ASSERT_GE(map_b, 0, "map_b"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_b, path), "pin_b"))
		goto out;

	err = getxattr(path, "user.k", buf, sizeof(buf));
	ASSERT_EQ(err, -1, "fresh_inode_ret");
	ASSERT_EQ(errno, ENODATA, "fresh_inode_errno");
out:
	if (map_a >= 0)
		close(map_a);
	if (map_b >= 0)
		close(map_b);
	umount_bpffs(dir);
}

static void test_umount_lifetime(void)
{
	char dir[64], path[128], buf[16];
	int map_fd = -1, err;

	if (!ASSERT_OK(mount_bpffs(dir), "mount"))
		return;
	snprintf(path, sizeof(path), "%s/m", dir);

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "x", 4, 4, 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, path), "pin"))
		goto out;
	ASSERT_OK(setxattr(path, "user.k", val_a, sizeof(val_a), XATTR_CREATE),
		  "set");

	close(map_fd);
	map_fd = -1;

	if (!ASSERT_OK(umount(dir), "umount"))
		goto out;
	if (!ASSERT_OK(mount("bpf", dir, "bpf", 0, NULL), "mount_fresh"))
		goto out;

	err = access(path, F_OK);
	ASSERT_EQ(err, -1, "path_gone_ret");
	ASSERT_EQ(errno, ENOENT, "path_gone_errno");

	err = getxattr(dir, "user.k", buf, sizeof(buf));
	ASSERT_EQ(err, -1, "root_xattr_gone_ret");
	ASSERT_EQ(errno, ENODATA, "root_xattr_gone_errno");
out:
	if (map_fd >= 0)
		close(map_fd);
	umount(dir);
	rmdir(dir);
}

void test_bpffs_xattr(void)
{
	if (test__start_subtest("prefixes"))
		test_prefixes();
	if (test__start_subtest("unsupported_prefix"))
		test_unsupported_prefix();
	if (test__start_subtest("flags"))
		test_flags();
	if (test__start_subtest("inode_types"))
		test_inode_types();
	if (test__start_subtest("repin_same_path"))
		test_repin_same_path();
	if (test__start_subtest("umount_lifetime"))
		test_umount_lifetime();
}
