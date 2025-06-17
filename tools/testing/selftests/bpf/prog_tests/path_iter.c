// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "path_iter.skel.h"
#include "path_walk.skel.h"

static const char grand_parent_path[] = "/tmp/test_progs_path_iter";
static const char parent_path[] = "/tmp/test_progs_path_iter/folder";
static const char file_path[] = "/tmp/test_progs_path_iter/folder/file";
static const char xattr_name[] = "user.bpf.selftests";
static const char xattr_value[] = "selftest_path_iter";

static void cleanup_files(void)
{
	remove(file_path);
	rmdir(parent_path);
	rmdir(grand_parent_path);
}

static int setup_files_and_xattrs(void)
{
	int ret = -1;

	/* create test folders */
	if (mkdir(grand_parent_path, 0755))
		goto error;
	if (mkdir(parent_path, 0755))
		goto error;

	/* setxattr for test folders */
	ret = setxattr(grand_parent_path, xattr_name,
		       xattr_value, sizeof(xattr_value), 0);
	if (ret < 0) {
		/* return errno, so that we can handle EOPNOTSUPP in the caller */
		ret = errno;
		goto error;
	}
	ret = setxattr(parent_path, xattr_name,
		       xattr_value, sizeof(xattr_value), 0);
	if (ret < 0) {
		/* return errno, so that we can handle EOPNOTSUPP in the caller */
		ret = errno;
		goto error;
	}

	return 0;
error:
	cleanup_files();
	return ret;
}

static void test_path_walk(void)
{
	struct path_walk *skel = NULL;
	int file_fd;
	int err;

	err = setup_files_and_xattrs();
	if (err == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		return;
	}

	if (!ASSERT_OK(err, "setup_file"))
		return;

	skel = path_walk__open_and_load();
	if (!ASSERT_OK_PTR(skel, "path_walk__open_and_load"))
		goto cleanup;

	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(path_walk__attach(skel), "path_walk__attach"))
		goto cleanup;

	file_fd = open(file_path, O_CREAT);
	if (!ASSERT_OK_FD(file_fd, "open_file"))
		goto cleanup;
	close(file_fd);

	ASSERT_OK(strncmp(skel->bss->parent_xattr_buf, xattr_value, strlen(xattr_value)),
		  "parent_xattr");
	ASSERT_OK(strncmp(skel->bss->grand_parent_xattr_buf, xattr_value, strlen(xattr_value)),
		  "grand_parent_xattr");

	ASSERT_OK(strncmp(skel->bss->parent_path_buf, parent_path, strlen(parent_path)),
		  "parent_d_path");
	ASSERT_OK(strncmp(skel->bss->grand_parent_path_buf, grand_parent_path,
			  strlen(grand_parent_path)),
		  "grand_parent_d_path");

cleanup:
	path_walk__destroy(skel);
	cleanup_files();
}

void test_path_iter(void)
{
	RUN_TESTS(path_iter);
	if (test__start_subtest("path_walk_example"))
		test_path_walk();
}
