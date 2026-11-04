// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "file_open_name.skel.h"

static void check_open(struct file_open_name *skel, int dfd, const char *name,
		       int flags, mode_t mode, int error)
{
	int fd, saved_errno;

	skel->bss->calls = 0;
	skel->bss->rcu_calls = 0;
	skel->bss->deny = error != 0;
	skel->bss->check_enabled = true;
	fd = openat(dfd, name, flags, mode);
	saved_errno = errno;
	skel->bss->check_enabled = false;

	if (error) {
		ASSERT_EQ(fd, -1, "deny open");
		ASSERT_EQ(saved_errno, error, "open errno");
	} else {
		ASSERT_OK_FD(fd, "allow open");
	}
	if (fd >= 0)
		close(fd);
	ASSERT_GT(skel->bss->calls, 0, "hook count");
	ASSERT_STREQ(skel->bss->pathname, name, "raw pathname");
	ASSERT_EQ(skel->bss->observed_flags & flags, flags, "open flags");
	ASSERT_EQ(skel->bss->observed_mode & 0777, mode, "creation mode");
}

void test_file_open_name(void)
{
	char dir[] = "/tmp/file_open_name.XXXXXX";
	struct file_open_name *skel = NULL;
	int dfd = -1, fd = -1;
	struct stat st;

	if (!ASSERT_OK_PTR(mkdtemp(dir), "mkdtemp"))
		return;
	dfd = open(dir, O_RDONLY | O_DIRECTORY);
	if (!ASSERT_OK_FD(dfd, "open directory"))
		goto out;
	fd = openat(dfd, "target", O_CREAT | O_RDWR, 0600);
	if (!ASSERT_OK_FD(fd, "create target"))
		goto out;
	if (!ASSERT_EQ(write(fd, "data", 4), 4, "write target"))
		goto out;
	if (!ASSERT_OK(symlinkat("target", dfd, "alias"), "symlink"))
		goto out;

	skel = file_open_name__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	if (!ASSERT_OK(stat("/proc/self/ns/pid", &st), "stat PID namespace"))
		goto out;
	skel->bss->pidns_dev = st.st_dev;
	skel->bss->pidns_ino = st.st_ino;
	skel->bss->monitored_tgid = getpid();
	if (!ASSERT_OK(file_open_name__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("raw_symlink")) {
		check_open(skel, dfd, "./alias", O_RDONLY, 0, 0);
		if (ASSERT_OK(fstat(dfd, &st), "stat base"))
			ASSERT_EQ(skel->bss->base_ino, st.st_ino, "dirfd base inode");
	}

	if (test__start_subtest("deny_create")) {
		check_open(skel, dfd, "new", O_CREAT | O_RDWR, 0600, EPERM);
		ASSERT_EQ(fstatat(dfd, "new", &st, 0), -1, "file not created");
		ASSERT_EQ(errno, ENOENT, "missing file");
	}
	if (test__start_subtest("deny_truncate")) {
		check_open(skel, dfd, "target", O_WRONLY | O_TRUNC, 0, EPERM);
		if (ASSERT_OK(fstat(fd, &st), "stat target"))
			ASSERT_EQ(st.st_size, 4, "file not truncated");
	}
	if (test__start_subtest("deny_o_path"))
		check_open(skel, dfd, "alias", O_PATH, 0, EPERM);
	if (test__start_subtest("deny_tmpfile"))
		check_open(skel, dfd, ".", O_TMPFILE | O_RDWR, 0600, EPERM);
	if (test__start_subtest("rcu_retry")) {
		skel->bss->require_ref = true;
		check_open(skel, dfd, "target", O_RDONLY, 0, EPERM);
		skel->bss->require_ref = false;
		ASSERT_EQ(skel->bss->calls, 2, "hook count");
		ASSERT_EQ(skel->bss->rcu_calls, 1, "RCU hook count");
	}
out:
	file_open_name__destroy(skel);
	if (fd >= 0)
		close(fd);
	if (dfd >= 0) {
		unlinkat(dfd, "alias", 0);
		unlinkat(dfd, "new", 0);
		unlinkat(dfd, "target", 0);
		close(dfd);
	}
	rmdir(dir);
}
