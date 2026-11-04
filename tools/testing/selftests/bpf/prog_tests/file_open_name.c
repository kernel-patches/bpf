// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "file_open_name.skel.h"

static void check_open_result(int fd, int error, const char *name)
{
	int saved_errno = errno;

	if (error) {
		ASSERT_EQ(fd, -1, name);
		ASSERT_EQ(saved_errno, error, "open errno");
	} else {
		ASSERT_OK_FD(fd, name);
	}
	if (fd >= 0)
		close(fd);
}

static void check_open(struct file_open_name *skel, int dfd, const char *name, int flags, mode_t mode, int error)
{
	int fd;

	skel->bss->calls = 0;
	skel->bss->check_enabled = true;
	fd = syscall(__NR_openat, dfd, name, flags, mode);
	skel->bss->check_enabled = false;
	check_open_result(fd, error, "open");
	ASSERT_GT(skel->bss->calls, 0, "hook count");
	ASSERT_STREQ(skel->bss->pathname, name, "raw pathname");
	ASSERT_EQ(skel->bss->observed_flags & flags, flags, "open flags");
	ASSERT_EQ(skel->bss->observed_mode & 0777, mode, "creation mode");
}

static void check_handle_open(struct file_open_name *skel, int dfd, int target_fd)
{
	static const struct {
		const char *name;
		int flags;
		int error;
	} cases[] = {
		{ "allow handle", O_RDONLY, 0 },
		{ "deny handle", O_RDONLY, EPERM },
		{ "deny handle truncate", O_WRONLY | O_TRUNC, EPERM },
		{ "deny handle O_PATH", O_PATH, EPERM },
	};
	struct file_handle *handle;
	int mount_id, fd, err, i;
	struct stat before, after;

	if (!ASSERT_OK(fstat(target_fd, &before), "stat handle target"))
		return;
	handle = calloc(1, sizeof(*handle) + MAX_HANDLE_SZ);
	if (!ASSERT_OK_PTR(handle, "allocate handle"))
		return;
	handle->handle_bytes = MAX_HANDLE_SZ;
	err = syscall(__NR_name_to_handle_at, dfd, "target", handle, &mount_id, 0);
	if (err < 0 && (errno == ENOSYS || errno == EOPNOTSUPP || errno == EPERM || errno == EACCES)) {
		printf("%s:SKIP:file handles are unavailable: %s\n", __func__, strerror(errno));
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "get file handle"))
		goto out;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		skel->bss->deny = cases[i].error != 0;
		skel->bss->calls = 0;
		skel->bss->check_enabled = true;
		fd = syscall(__NR_open_by_handle_at, dfd, handle, cases[i].flags);
		skel->bss->check_enabled = false;
		/* The first allowed open also probes handle support. */
		if (!i && !skel->bss->calls && fd < 0 &&
		    (errno == ENOSYS || errno == EOPNOTSUPP || errno == EPERM || errno == EACCES)) {
			printf("%s:SKIP:opening file handles is unavailable: %s\n", __func__, strerror(errno));
			test__skip();
			goto out;
		}
		check_open_result(fd, cases[i].error, cases[i].name);
		ASSERT_EQ(skel->bss->calls, 1, "handle hook count");
		ASSERT_STREQ(skel->bss->pathname, "", "empty handle pathname");
		ASSERT_EQ(skel->bss->observed_flags & cases[i].flags, cases[i].flags, "handle open flags");
		ASSERT_EQ(skel->bss->observed_mode, 0, "handle open mode");
	}
	if (ASSERT_OK(fstat(target_fd, &after), "stat handle target after opens"))
		ASSERT_EQ(after.st_size, before.st_size, "handle target not truncated");
out:
	free(handle);
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
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(file_open_name__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("raw_symlink"))
		check_open(skel, dfd, "./alias", O_RDONLY, 0, 0);

	skel->bss->deny = true;
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
	if (test__start_subtest("handle_open"))
		check_handle_open(skel, dfd, fd);
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
