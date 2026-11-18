// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kselftest_harness.h"
#include "../wrappers.h"

static int setup_tmp(void)
{
	if (unshare(CLONE_NEWNS))
		return -errno;
	if (sys_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return -errno;
	if (sys_mount("tmpfs", "/tmp", "tmpfs", 0, NULL))
		return -errno;
	if (mkdir("/tmp/lower", 0755) || mkdir("/tmp/data", 0755) ||
	    mkdir("/tmp/upper", 0755) || mkdir("/tmp/work", 0755) ||
	    mkdir("/tmp/merged", 0755))
		return -errno;
	return 0;
}

/* Mount an overlayfs with the legacy "lowerdir=" option and extra options. */
static int mount_lowerdir_opts(const char *lowerdir, const char *extra)
{
	char opts[256];

	snprintf(opts, sizeof(opts), "lowerdir=%s%s%s", lowerdir,
		 extra ? "," : "", extra ? extra : "");
	if (sys_mount("overlay", "/tmp/merged", "overlay", MS_RDONLY, opts))
		return -errno;
	if (umount2("/tmp/merged", 0))
		return -errno;
	return 0;
}

static int mount_lowerdir(const char *lowerdir)
{
	return mount_lowerdir_opts(lowerdir, NULL);
}

static int set_layer(int fd_context, const char *key, const char *path,
		     bool by_fd)
{
	int fd, ret = 0;

	if (!by_fd) {
		if (sys_fsconfig(fd_context, FSCONFIG_SET_STRING, key, path, 0))
			return -errno;
		return 0;
	}

	fd = open(path, O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (sys_fsconfig(fd_context, FSCONFIG_SET_FD, key, NULL, fd))
		ret = -errno;
	close(fd);
	return ret;
}

/* Mount an overlayfs with the legacy "upperdir=" and "workdir=" options. */
static int mount_upperdir(const char *upper, const char *work)
{
	char opts[256];

	snprintf(opts, sizeof(opts), "lowerdir=/tmp/lower,upperdir=%s,workdir=%s",
		 upper, work);
	if (sys_mount("overlay", "/tmp/merged", "overlay", 0, opts))
		return -errno;
	if (umount2("/tmp/merged", 0))
		return -errno;
	return 0;
}

/* Mount an overlayfs with an upper layer and extra options. */
static int mount_upper_opts(const char *lowerdir, const char *upper,
			    const char *work, const char *extra)
{
	char opts[256];

	snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s,%s",
		 lowerdir, upper, work, extra);
	if (sys_mount("overlay", "/tmp/merged", "overlay", 0, opts))
		return -errno;
	if (umount2("/tmp/merged", 0))
		return -errno;
	return 0;
}

/* The index needs xattrs and file handles on the upper layer. */
static bool have_index(void)
{
	struct stat st;

	if (mkdir("/tmp/iupper", 0755) || mkdir("/tmp/iwork", 0755))
		return false;
	if (mount_upper_opts("/tmp/lower", "/tmp/iupper", "/tmp/iwork",
			     "index=on"))
		return false;
	return !stat("/tmp/iwork/index", &st);
}

/* Create an overlayfs with "upperdir" and "workdir" through fsconfig. */
static int fsmount_upper(const char *upper, const char *work, bool by_fd)
{
	int fd_context, fd_mnt, ret;

	fd_context = sys_fsopen("overlay", FSOPEN_CLOEXEC);
	if (fd_context < 0)
		return -errno;

	ret = set_layer(fd_context, "lowerdir+", "/tmp/lower", by_fd);
	if (ret)
		goto out;
	ret = set_layer(fd_context, "upperdir", upper, by_fd);
	if (ret)
		goto out;
	ret = set_layer(fd_context, "workdir", work, by_fd);
	if (ret)
		goto out;

	if (sys_fsconfig(fd_context, FSCONFIG_CMD_CREATE, NULL, NULL, 0)) {
		ret = -errno;
		goto out;
	}

	fd_mnt = sys_fsmount(fd_context, FSMOUNT_CLOEXEC, 0);
	if (fd_mnt < 0)
		ret = -errno;
	else
		close(fd_mnt);
out:
	close(fd_context);
	return ret;
}

/* Create an overlayfs with "lowerdir+" and "datadir+" through fsconfig. */
static int fsmount_layers(const char *lower, const char *data, bool by_fd)
{
	int fd_context, fd_mnt, ret;

	fd_context = sys_fsopen("overlay", FSOPEN_CLOEXEC);
	if (fd_context < 0)
		return -errno;

	ret = set_layer(fd_context, "lowerdir+", lower, by_fd);
	if (ret)
		goto out;
	ret = set_layer(fd_context, "datadir+", data, by_fd);
	if (ret)
		goto out;

	if (sys_fsconfig(fd_context, FSCONFIG_CMD_CREATE, NULL, NULL, 0)) {
		ret = -errno;
		goto out;
	}

	fd_mnt = sys_fsmount(fd_context, FSMOUNT_CLOEXEC, 0);
	if (fd_mnt < 0)
		ret = -errno;
	else
		close(fd_mnt);
out:
	close(fd_context);
	return ret;
}

TEST(datadir_sysfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir("/tmp/lower::/sys/kernel"), -EINVAL);
	EXPECT_EQ(fsmount_layers("/tmp/lower", "/sys/kernel", false), -EINVAL);
	EXPECT_EQ(fsmount_layers("/tmp/lower", "/sys/kernel", true), -EINVAL);
}

TEST(datadir_procfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir("/tmp/lower::/proc"), -EINVAL);
	EXPECT_EQ(fsmount_layers("/tmp/lower", "/proc", false), -EINVAL);
	EXPECT_EQ(fsmount_layers("/tmp/lower", "/proc", true), -EINVAL);
}

TEST(datadir_tmpfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir("/tmp/lower::/tmp/data"), 0);
	EXPECT_EQ(fsmount_layers("/tmp/lower", "/tmp/data", false), 0);
	EXPECT_EQ(fsmount_layers("/tmp/lower", "/tmp/data", true), 0);
}

/*
 * Pseudo lower layers are only allowed in legacy setups.  Explicitly turn off
 * the features that may be enabled by kernel config defaults.
 */
#define LEGACY_OPTS "redirect_dir=off,metacopy=off"

TEST(lowerdir_sysfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir_opts("/sys/kernel:/tmp/lower", LEGACY_OPTS), 0);
}

TEST(lowerdir_sysfs_redirect_dir_on)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir_opts("/sys/kernel:/tmp/lower",
				      "redirect_dir=on"), -EINVAL);
}

TEST(lowerdir_sysfs_with_datadir)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir("/sys/kernel::/tmp/data"), -EINVAL);
	EXPECT_EQ(fsmount_layers("/sys/kernel", "/tmp/data", false), -EINVAL);
	EXPECT_EQ(fsmount_layers("/sys/kernel", "/tmp/data", true), -EINVAL);
}

#define INDEX_OPTS "index=on," LEGACY_OPTS

/*
 * sysfs and ramfs don't support file handles, so the index falls back to off
 * and the mount is a legacy setup, whatever the order of the lower layers.
 */
TEST(lowerdir_sysfs_index)
{
	ASSERT_EQ(setup_tmp(), 0);
	if (!have_index())
		SKIP(return, "overlayfs index not supported on tmpfs");
	ASSERT_EQ(mkdir("/tmp/ramfs", 0755), 0);
	ASSERT_EQ(sys_mount("ramfs", "/tmp/ramfs", "ramfs", 0, NULL), 0);

	EXPECT_EQ(mount_upper_opts("/sys/kernel", "/tmp/upper", "/tmp/work",
				   INDEX_OPTS), 0);
	EXPECT_EQ(mount_upper_opts("/tmp/lower:/sys/kernel", "/tmp/upper",
				   "/tmp/work", INDEX_OPTS), 0);
	EXPECT_EQ(mount_upper_opts("/sys/kernel:/tmp/ramfs", "/tmp/upper",
				   "/tmp/work", INDEX_OPTS), 0);
	EXPECT_EQ(mount_upper_opts("/tmp/ramfs:/sys/kernel", "/tmp/upper",
				   "/tmp/work", INDEX_OPTS), 0);
}

/*
 * Like CONFIG_OVERLAY_FS_NFS_EXPORT=y with redirect_dir=off and
 * CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=n: nfs_export turns on the index in
 * a non-upper mount that never uses it.  sysfs doesn't support file handles,
 * so both fall back to off.
 */
#define NFS_EXPORT_OPTS "nfs_export=on,redirect_dir=nofollow,metacopy=off"

TEST(lowerdir_sysfs_nfs_export)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir_opts("/sys/kernel:/tmp/lower",
				      NFS_EXPORT_OPTS), 0);
	EXPECT_EQ(mount_lowerdir_opts("/tmp/lower:/sys/kernel",
				      NFS_EXPORT_OPTS), 0);
}

/*
 * cgroup2 supports file handles, so the index stays on and cgroup2 is refused
 * as lower layer, unless the mount falls back to read-only without a workdir.
 */
TEST(lowerdir_cgroup2_index)
{
	ASSERT_EQ(setup_tmp(), 0);
	if (!have_index())
		SKIP(return, "overlayfs index not supported on tmpfs");
	ASSERT_EQ(mkdir("/tmp/cgroup", 0755), 0);
	if (sys_mount("cgroup2", "/tmp/cgroup", "cgroup2", 0, NULL))
		SKIP(return, "cgroup2 not supported");

	EXPECT_EQ(mount_upper_opts("/tmp/cgroup", "/tmp/upper", "/tmp/work",
				   INDEX_OPTS), -EINVAL);
	EXPECT_EQ(mount_upper_opts("/tmp/cgroup", "/tmp/upper", "/tmp/work",
				   "index=off," LEGACY_OPTS), 0);

	/* A tmpfs with three inodes has no room for the workdir */
	ASSERT_EQ(mkdir("/tmp/full", 0755), 0);
	ASSERT_EQ(sys_mount("tmpfs", "/tmp/full", "tmpfs", 0, "nr_inodes=3"), 0);
	ASSERT_EQ(mkdir("/tmp/full/upper", 0755), 0);
	ASSERT_EQ(mkdir("/tmp/full/work", 0755), 0);
	EXPECT_EQ(mount_upper_opts("/tmp/cgroup", "/tmp/full/upper",
				   "/tmp/full/work", INDEX_OPTS), 0);
}

/*
 * Without the check, sysfs as upperdir falls back to a read-only mount
 * because the work dir cannot be created.
 */
TEST(upperdir_sysfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_upperdir("/sys/block", "/sys/bus"), -EINVAL);
	EXPECT_EQ(fsmount_upper("/sys/block", "/sys/bus", false), -EINVAL);
	EXPECT_EQ(fsmount_upper("/sys/block", "/sys/bus", true), -EINVAL);
}

TEST(upperdir_tmpfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_upperdir("/tmp/upper", "/tmp/work"), 0);
	EXPECT_EQ(fsmount_upper("/tmp/upper", "/tmp/work", false), 0);
	EXPECT_EQ(fsmount_upper("/tmp/upper", "/tmp/work", true), 0);
}

TEST_HARNESS_MAIN
