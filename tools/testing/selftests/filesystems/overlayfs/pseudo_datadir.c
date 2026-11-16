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
	    mkdir("/tmp/merged", 0755))
		return -errno;
	return 0;
}

/* Mount an overlayfs with the legacy "lowerdir=" option. */
static int mount_lowerdir(const char *lowerdir)
{
	char opts[256];

	snprintf(opts, sizeof(opts), "lowerdir=%s", lowerdir);
	if (sys_mount("overlay", "/tmp/merged", "overlay", MS_RDONLY, opts))
		return -errno;
	if (umount2("/tmp/merged", 0))
		return -errno;
	return 0;
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

TEST(lowerdir_sysfs)
{
	ASSERT_EQ(setup_tmp(), 0);

	EXPECT_EQ(mount_lowerdir("/sys/kernel:/tmp/lower"), 0);
	EXPECT_EQ(mount_lowerdir("/sys/kernel::/tmp/data"), 0);
	EXPECT_EQ(fsmount_layers("/sys/kernel", "/tmp/data", false), 0);
	EXPECT_EQ(fsmount_layers("/sys/kernel", "/tmp/data", true), 0);
}

TEST_HARNESS_MAIN
