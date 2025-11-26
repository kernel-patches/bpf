// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. */

#include <test_progs.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "test_kern_path.skel.h"
#include "verifier_kern_path.skel.h"
#include "verifier_kern_path_fail.skel.h"

static void __test_kern_path(void (*trigger)(void))
{
	struct test_kern_path *skel;
	int err;

	skel = test_kern_path__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_kern_path__open_and_load"))
		return;

	skel->bss->monitored_pid = getpid();

	err = test_kern_path__attach(skel);
	if (!ASSERT_OK(err, "test_kern_path__attach"))
		goto cleanup;

	trigger();

	/* Verify the bpf_path_d_path worked */
	ASSERT_GT(skel->bss->path_len, 0, "path_len > 0");

cleanup:
	test_kern_path__destroy(skel);
}

static void trigger_file_open(void)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	if (!ASSERT_OK_FD(fd, "open /dev/null"))
		return;
	close(fd);
}

static void trigger_sb_mount(void)
{
	char tmpdir[] = "/tmp/bpf_kern_path_test_XXXXXX";
	int err;

	if (!ASSERT_OK_PTR(mkdtemp(tmpdir), "mkdtemp"))
		return;

	err = mount("/tmp", tmpdir, NULL, MS_BIND, NULL);
	if (!ASSERT_OK(err, "bind mount"))
		goto rmdir;

	umount(tmpdir);
rmdir:
	rmdir(tmpdir);
}

void test_kern_path(void)
{
	if (test__start_subtest("file_open"))
		__test_kern_path(trigger_file_open);

	if (test__start_subtest("sb_mount"))
		__test_kern_path(trigger_sb_mount);
}

void test_verifier_kern_path(void)
{
	RUN_TESTS(verifier_kern_path);
}

void test_verifier_kern_path_fail(void)
{
	RUN_TESTS(verifier_kern_path_fail);
}
