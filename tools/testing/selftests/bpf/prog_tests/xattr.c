// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Google LLC.
 */

#include <test_progs.h>
#include <sys/xattr.h>
#include "xattr.skel.h"

#define XATTR_NAME "security.bpf"
#define XATTR_VALUE "test_progs"

void test_xattr(void)
{
	struct xattr *skel = NULL;
	char tmp_dir_path[] = "/tmp/xattrXXXXXX";
	char tmp_exec_path[64];
	char cmd[256];
	int err;

	if (CHECK_FAIL(!mkdtemp(tmp_dir_path)))
		goto close_prog;

	snprintf(tmp_exec_path, sizeof(tmp_exec_path), "%s/copy_of_ls",
		 tmp_dir_path);
	snprintf(cmd, sizeof(cmd), "cp /bin/ls %s", tmp_exec_path);
	if (CHECK_FAIL(system(cmd)))
		goto close_prog_rmdir;

	if (CHECK_FAIL(setxattr(tmp_exec_path, XATTR_NAME, XATTR_VALUE,
			   sizeof(XATTR_VALUE), 0)))
		goto close_prog_rmdir;

	skel = xattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto close_prog_rmdir;

	err = xattr__attach(skel);
	if (!ASSERT_OK(err, "xattr__attach failed"))
		goto close_prog_rmdir;

	snprintf(cmd, sizeof(cmd), "%s -l", tmp_exec_path);
	if (CHECK_FAIL(system(cmd)))
		goto close_prog_rmdir;

	ASSERT_EQ(skel->bss->result, 1, "xattr result");

close_prog_rmdir:
	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir_path);
	system(cmd);
close_prog:
	xattr__destroy(skel);
}
