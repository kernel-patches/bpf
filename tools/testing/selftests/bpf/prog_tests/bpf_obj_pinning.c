// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <linux/mount.h>
#include <sys/syscall.h>

static inline int sys_fsopen(const char *fsname, unsigned flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}

static inline int sys_fsconfig(int fs_fd, unsigned cmd, const char *key, const void *val, int aux)
{
	return syscall(__NR_fsconfig, fs_fd, cmd, key, val, aux);
}

static inline int sys_fsmount(int fs_fd, unsigned flags, unsigned ms_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, ms_flags);
}

static inline int sys_move_mount(int from_dfd, const char *from_path,
			         int to_dfd, const char *to_path,
			         unsigned int ms_flags)
{
	return syscall(__NR_move_mount, from_dfd, from_path, to_dfd, to_path, ms_flags);
}

void test_bpf_obj_pinning(void)
{
	LIBBPF_OPTS(bpf_obj_pin_opts, pin_opts);
	LIBBPF_OPTS(bpf_obj_get_opts, get_opts);
	int fs_fd = -1, mnt_fd = -1;
	int map_fd = -1, map_fd2 = -1;
	int zero = 0, src_value, dst_value, err;
	const char *map_name = "fsmount_map";

	/* A bunch of below UAPI calls are constructed based on reading:
	 * https://brauner.io/2023/02/28/mounting-into-mount-namespaces.html
	 */

	/* create VFS context */
	fs_fd = sys_fsopen("bpf", 0);
	if (!ASSERT_GE(fs_fd, 0, "fs_fd"))
		goto cleanup;

	/* instantiate FS object */
	err = sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (!ASSERT_OK(err, "fs_create"))
		goto cleanup;

	/* create O_PATH fd for detached mount */
	mnt_fd = sys_fsmount(fs_fd, 0, 0);
	if (!ASSERT_GE(mnt_fd, 0, "mnt_fd"))
		goto cleanup;

	/* If we wanted to expose detached mount in the file system, we'd do
	 * something like below. But the whole point is that we actually don't
	 * even have to expose BPF FS in the file system to be able to work
	 * (pin/get objects) with it.
	 *
	 * err = sys_move_mount(mnt_fd, "", -EBADF, mnt_path, MOVE_MOUNT_F_EMPTY_PATH);
	 * if (!ASSERT_OK(err, "move_mount"))
	 *	goto cleanup;
	 */

	/* create BPF map to pin */
	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, map_name, 4, 4, 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "map_fd"))
		goto cleanup;

	/* pin BPF map into detached BPF FS through mnt_fd */
	pin_opts.file_flags = BPF_F_PATH_FD;
	pin_opts.path_fd = mnt_fd;
	err = bpf_obj_pin_opts(map_fd, map_name, &pin_opts);
	if (!ASSERT_OK(err, "map_pin"))
		goto cleanup;

	/* get BPF map from detached BPF FS through mnt_fd */
	get_opts.file_flags = BPF_F_PATH_FD;
	get_opts.path_fd = mnt_fd;
	map_fd2 = bpf_obj_get_opts(map_name, &get_opts);
	if (!ASSERT_GE(map_fd2, 0, "map_get"))
		goto cleanup;

	/* update map through one FD */
	src_value = 0xcafebeef;
	err = bpf_map_update_elem(map_fd, &zero, &src_value, 0);
	ASSERT_OK(err, "map_update");

	/* check values written/read through different FDs do match */
	dst_value = 0;
	err = bpf_map_lookup_elem(map_fd2, &zero, &dst_value);
	ASSERT_OK(err, "map_lookup");
	ASSERT_EQ(dst_value, src_value, "map_value_eq1");
	ASSERT_EQ(dst_value, 0xcafebeef, "map_value_eq2");

cleanup:
	if (map_fd >= 0)
		ASSERT_OK(close(map_fd), "close_map_fd");
	if (map_fd2 >= 0)
		ASSERT_OK(close(map_fd2), "close_map_fd2");
	if (fs_fd >= 0)
		ASSERT_OK(close(fs_fd), "close_fs_fd");
	if (mnt_fd >= 0)
		ASSERT_OK(close(mnt_fd), "close_mnt_fd");
}
