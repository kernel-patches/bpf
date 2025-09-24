// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 David Windsor <dwindsor@gmail.com> */

#include <test_progs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "dentry_lsm.skel.h"

void test_dentry_lsm(void)
{
	struct dentry_lsm *skel;
	char test_file[PATH_MAX];
	int fd, ret;

	skel = dentry_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "dentry_lsm__open_and_load"))
		return;

	ret = dentry_lsm__attach(skel);
	if (!ASSERT_OK(ret, "dentry_lsm__attach"))
		goto cleanup;

	/* Create a temporary file to trigger file_open LSM hook */
	ret = snprintf(test_file, sizeof(test_file), "/tmp/bpf_test_file_%d", getpid());
	if (!ASSERT_GT(ret, 0, "snprintf"))
		goto cleanup_link;
	if (!ASSERT_LT(ret, sizeof(test_file), "snprintf"))
		goto cleanup_link;

	fd = open(test_file, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "open"))
		goto cleanup_link;
	close(fd);

	/* Test passes if BPF program loaded and ran without error */

	/* Clean up test file */
	unlink(test_file);

cleanup_link:
	unlink(test_file);
cleanup:
	dentry_lsm__destroy(skel);
}
