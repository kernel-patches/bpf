// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 */

#include <errno.h>
#include <limits.h>
#include <test_progs.h>
#include <sys/mount.h>
#include <sys/stat.h>

#define MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME)

static int duration;

void test_test_preload_methods(void)
{
	char bpf_mntpoint[] = "/tmp/bpf_mntpointXXXXXX", *dir;
	char path[PATH_MAX];
	struct stat st;
	int err;

	system("rmmod bpf_testmod_preload 2> /dev/null");

	err = system("insmod bpf_testmod_preload.ko");
	if (CHECK(err, "insmod",
		  "cannot load bpf_testmod_preload.ko, err=%d\n", err))
		return;

	dir = mkdtemp(bpf_mntpoint);
	if (CHECK(!dir, "mkstemp", "cannot create temp file, err=%d\n",
		  -errno))
		goto out_rmmod;

	err = mount(bpf_mntpoint, bpf_mntpoint, "bpf", MOUNT_FLAGS, NULL);
	if (CHECK(err, "mount",
		  "cannot mount bpf filesystem to %s, err=%d\n", bpf_mntpoint,
		  err))
		goto out_unlink;

	snprintf(path, sizeof(path), "%s/gen_preload_methods_lskel",
		 bpf_mntpoint);

	err = stat(path, &st);
	if (CHECK(err, "stat", "cannot find %s\n", path))
		goto out_unmount;

	snprintf(path, sizeof(path),
		 "%s/gen_preload_methods_lskel/dump_bpf_map", bpf_mntpoint);

	err = stat(path, &st);
	if (CHECK(err, "stat", "cannot find %s\n", path))
		goto out_unmount;

	snprintf(path, sizeof(path), "%s/gen_preload_methods_lskel/ringbuf",
		 bpf_mntpoint);

	err = stat(path, &st);
	if (CHECK(err, "stat", "cannot find %s\n", path))
		goto out_unmount;

out_unmount:
	umount(bpf_mntpoint);
out_unlink:
	rmdir(bpf_mntpoint);
out_rmmod:
	system("rmmod bpf_testmod_preload");
}
