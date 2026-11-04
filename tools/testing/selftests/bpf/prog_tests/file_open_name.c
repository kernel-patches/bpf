// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <io_uring/mini_liburing.h>
#include "file_open_name.skel.h"

static void check_open(struct file_open_name *skel, int dfd, const char *name,
		       int flags, mode_t mode, int error)
{
	int fd, saved_errno;

	skel->bss->calls = 0;
	skel->bss->check_enabled = true;
	fd = syscall(__NR_openat, dfd, name, flags, mode);
	skel->bss->check_enabled = false;
	saved_errno = errno;
	if (error) {
		ASSERT_EQ(fd, -1, "open denied");
		ASSERT_EQ(saved_errno, error, "open errno");
	} else {
		ASSERT_OK_FD(fd, "open allowed");
	}
	if (fd >= 0)
		close(fd);
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
	int mount_id, fd, err, saved_errno, i;
	struct stat before, after;

	if (!ASSERT_OK(fstat(target_fd, &before), "stat handle target"))
		return;
	handle = calloc(1, sizeof(*handle) + MAX_HANDLE_SZ);
	if (!ASSERT_OK_PTR(handle, "allocate handle"))
		return;
	handle->handle_bytes = MAX_HANDLE_SZ;
	err = syscall(__NR_name_to_handle_at, dfd, "target", handle, &mount_id, 0);
	if (err < 0 && (errno == ENOSYS || errno == EOPNOTSUPP ||
			errno == EPERM || errno == EACCES)) {
		printf("%s:SKIP:file handles are unavailable: %s\n",
		       __func__, strerror(errno));
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "get file handle"))
		goto out;

	fd = syscall(__NR_open_by_handle_at, dfd, handle, O_RDONLY);
	if (fd < 0 && (errno == ENOSYS || errno == EOPNOTSUPP ||
		       errno == EPERM || errno == EACCES)) {
		printf("%s:SKIP:opening file handles is unavailable: %s\n",
		       __func__, strerror(errno));
		test__skip();
		goto out;
	}
	if (!ASSERT_OK_FD(fd, "probe handle open"))
		goto out;
	close(fd);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		skel->bss->deny = cases[i].error != 0;
		skel->bss->calls = 0;
		skel->bss->check_enabled = true;
		fd = syscall(__NR_open_by_handle_at, dfd, handle, cases[i].flags);
		skel->bss->check_enabled = false;
		saved_errno = errno;
		if (fd >= 0)
			close(fd);
		if (cases[i].error) {
			ASSERT_EQ(fd, -1, cases[i].name);
			ASSERT_EQ(saved_errno, cases[i].error, "handle open errno");
		} else {
			ASSERT_OK_FD(fd, cases[i].name);
		}
		ASSERT_EQ(skel->bss->calls, 1, "handle hook count");
		ASSERT_STREQ(skel->bss->pathname, "", "empty handle pathname");
		ASSERT_EQ(skel->bss->observed_flags & cases[i].flags,
			  cases[i].flags, "handle open flags");
		ASSERT_EQ(skel->bss->observed_mode, 0, "handle open mode");
	}
	if (ASSERT_OK(fstat(target_fd, &after), "stat handle target after opens"))
		ASSERT_EQ(after.st_size, before.st_size, "handle target not truncated");
out:
	free(handle);
}

static void check_uring(struct file_open_name *skel, int dfd)
{
	static const struct {
		const char *test;
		const char *name;
		int flags;
		int error;
	} cases[] = {
		{ "uring_worker", "./alias", O_RDONLY },
		{ "uring_deny", "uring_new", O_CREAT | O_RDWR, EPERM },
	};
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	bool initialized = false;
	int err, i, result;
	struct stat st;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!test__start_subtest(cases[i].test))
			continue;
		if (!initialized) {
			err = io_uring_queue_init(1, &ring, 0);
			if (err == -1 && (errno == ENOSYS || errno == EPERM)) {
				printf("%s:SKIP:io_uring is unavailable: %s\n",
				       __func__, strerror(errno));
				test__skip();
				continue;
			}
			if (!ASSERT_OK(err, "io_uring setup"))
				return;
			initialized = true;
		}
		skel->bss->deny = cases[i].error != 0;
		skel->bss->calls = 0;
		sqe = io_uring_get_sqe(&ring);
		if (!ASSERT_OK_PTR(sqe, "get sqe"))
			break;
		memset(sqe, 0, sizeof(*sqe));
		sqe->opcode = IORING_OP_OPENAT;
		sqe->fd = dfd;
		sqe->addr = (unsigned long)cases[i].name;
		sqe->open_flags = cases[i].flags;
		sqe->len = 0600;
		sqe->flags = IOSQE_ASYNC;
		skel->bss->check_enabled = true;
		if (!ASSERT_EQ(io_uring_submit(&ring), 1, "submit"))
			break;
		if (!ASSERT_OK(io_uring_wait_cqe(&ring, &cqe), "wait cqe"))
			break;
		skel->bss->check_enabled = false;
		result = cqe->res;
		io_uring_cqe_seen(&ring);
		if (cases[i].error)
			ASSERT_EQ(result, -cases[i].error, "cqe error");
		else
			ASSERT_OK_FD(result, "cqe success");
		if (result >= 0)
			close(result);
		ASSERT_GT(skel->bss->calls, 0, "io_uring hook count");
		ASSERT_STREQ(skel->bss->pathname, cases[i].name, "hook pathname");
	}
	if (!initialized)
		return;
	skel->bss->check_enabled = false;
	io_uring_queue_exit(&ring);
	ASSERT_EQ(fstatat(dfd, "uring_new", &st, 0), -1, "io_uring file not created");
	ASSERT_EQ(errno, ENOENT, "io_uring missing file");
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
	check_uring(skel, dfd);
	if (test__start_subtest("handle_open"))
		check_handle_open(skel, dfd, fd);
out:
	file_open_name__destroy(skel);
	if (fd >= 0)
		close(fd);
	if (dfd >= 0) {
		unlinkat(dfd, "alias", 0);
		unlinkat(dfd, "new", 0);
		unlinkat(dfd, "uring_new", 0);
		unlinkat(dfd, "target", 0);
		close(dfd);
	}
	rmdir(dir);
}
