// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <test_progs.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "refcounted_kptr_file_fail.skel.h"
#include "refcounted_kptr_file.skel.h"
#include "refcounted_kptr_file_success.skel.h"

static const char shell_path[] = "/bin/sh";
static const char xattr_name[] = "user.kptr_ref";
static const char xattr_value[] = "kptr-live";

static int write_full(int fd, const void *buf, size_t len)
{
	const char *pos = buf;

	while (len) {
		ssize_t written;

		written = write(fd, pos, len);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		pos += written;
		len -= written;
	}

	return 0;
}

static int copy_file(const char *src_path, const char *dst_path, mode_t mode)
{
	char buf[4096];
	int src_fd = -1, dst_fd = -1;
	int err = 0;

	src_fd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (src_fd < 0)
		return -errno;

	dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
		      mode & 0777);
	if (dst_fd < 0) {
		err = -errno;
		goto out;
	}

	while (1) {
		ssize_t bytes_read;

		bytes_read = read(src_fd, buf, sizeof(buf));
		if (bytes_read < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			goto out;
		}

		if (!bytes_read)
			break;

		err = write_full(dst_fd, buf, bytes_read);
		if (err) {
			unlink(dst_path);
			goto out;
		}
	}

out:
	if (src_fd >= 0 && close(src_fd) && !err)
		err = -errno;
	if (dst_fd >= 0 && close(dst_fd) && !err)
		err = -errno;
	return err;
}

static bool prepare_tagged_shell(char *temp_dir, size_t temp_dir_sz,
				 char *shell_copy, size_t shell_copy_sz)
{
	struct stat st;
	int err;

	if (!ASSERT_LT(snprintf(temp_dir, temp_dir_sz,
				"./refcounted_kptr_file.XXXXXX"),
		     (int)temp_dir_sz, "temp_dir_template"))
		return false;

	if (!ASSERT_OK_PTR(mkdtemp(temp_dir), "mkdtemp"))
		return false;

	if (!ASSERT_LT(snprintf(shell_copy, shell_copy_sz, "%s/sh", temp_dir),
		       (int)shell_copy_sz, "shell_copy_path"))
		goto err_rmdir;

	if (!ASSERT_OK(stat(shell_path, &st), "stat_shell"))
		goto err_rmdir;

	err = copy_file(shell_path, shell_copy, st.st_mode);
	if (!ASSERT_OK(err, "copy_shell"))
		goto err_unlink;

	err = setxattr(shell_copy, xattr_name, xattr_value, sizeof(xattr_value), 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:filesystem does not support user xattr (%d)\n",
		       __func__, errno);
		test__skip();
		goto err_unlink;
	}

	if (!ASSERT_OK(err, "setxattr_shell"))
		goto err_unlink;

	return true;

err_unlink:
	unlink(shell_copy);
err_rmdir:
	rmdir(temp_dir);
	return false;
}

static void run_refcounted_file_kptr_success(void)
{
	struct refcounted_kptr_file *skel;
	char shell_copy[PATH_MAX] = {};
	char temp_dir[PATH_MAX] = {};
	int pipefd[2] = { -1, -1 };
	int status;
	pid_t child_pid = -1;
	int err, fd = -1;

	skel = refcounted_kptr_file__open();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr_file__open"))
		return;

	err = refcounted_kptr_file__load(skel);
	if (!ASSERT_OK(err, "refcounted_kptr_file__load"))
		goto out;

	err = refcounted_kptr_file__attach(skel);
	if (!ASSERT_OK(err, "refcounted_kptr_file__attach"))
		goto out;

	if (!prepare_tagged_shell(temp_dir, sizeof(temp_dir), shell_copy,
				  sizeof(shell_copy)))
		goto out;

	if (!ASSERT_OK(pipe2(pipefd, O_CLOEXEC), "pipe2"))
		goto out;

	child_pid = fork();
	if (!ASSERT_GT(child_pid, -1, "fork"))
		goto out;

	if (child_pid == 0) {
		char sync;

		close(pipefd[1]);
		if (read(pipefd[0], &sync, 1) != 1)
			_exit(127);
		close(pipefd[0]);
		execl(shell_copy, shell_copy, "-c", ": </dev/null", NULL);
		_exit(127);
	}

	close(pipefd[0]);
	pipefd[0] = -1;

	/*
	 * Set the PID *before* unblocking the child so that the BPF program's
	 * file_open hook can filter on it from the very first file opened during
	 * exec.  If the write happened first, early file_open events during
	 * exec could be missed.
	 */
	skel->bss->file_kptr_insert_pid = child_pid;
	err = write_full(pipefd[1], "1", 1);
	if (!ASSERT_OK(err, "start_child"))
		goto out;
	close(pipefd[1]);
	pipefd[1] = -1;

	if (!ASSERT_EQ(waitpid(child_pid, &status, 0), child_pid, "waitpid"))
		goto out;
	child_pid = -1;
	if (!ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		goto out;
	if (!ASSERT_EQ(WEXITSTATUS(status), 0, "child_status"))
		goto out;

	skel->bss->file_kptr_verify_pid = getpid();
	/*
	 * The child is gone at this point. Reopening an unrelated file triggers a
	 * second file_open hook where the BPF program validates the stashed ref.
	 * Our test op for the ref validity is reading the xattrs we set earlier.
	 */
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (!ASSERT_GE(fd, 0, "open_dev_null"))
		goto out;
	close(fd);
	fd = -1;

	ASSERT_EQ(skel->bss->file_kptr_err, 0, "file_kptr_err");
	ASSERT_EQ(skel->bss->file_kptr_inserted, 1, "file_kptr_inserted");
	ASSERT_EQ(skel->bss->file_kptr_verified, 1, "file_kptr_verified");
	ASSERT_EQ(skel->bss->file_kptr_xattr_ret, sizeof(xattr_value),
		  "file_kptr_xattr_ret");
	ASSERT_EQ(strcmp(skel->bss->file_kptr_value, xattr_value), 0,
		  "file_kptr_value");

out:
	close(fd);
	close(pipefd[0]);
	close(pipefd[1]);
	if (child_pid > 0)
		(void)waitpid(child_pid, NULL, 0);
	if (shell_copy[0])
		unlink(shell_copy);
	if (temp_dir[0])
		rmdir(temp_dir);
	refcounted_kptr_file__destroy(skel);
}
void test_refcounted_kptr_file(void)
{
	RUN_TESTS(refcounted_kptr_file_success);

	RUN_TESTS(refcounted_kptr_file_fail);

	if (test__start_subtest("holds_ref_after_close"))
		run_refcounted_file_kptr_success();

	RUN_TESTS(refcounted_kptr_file);
}
