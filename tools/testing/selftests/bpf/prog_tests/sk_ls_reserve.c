// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "sk_ls_reserve.skel.h"

static int cgroup_fd;

static void test_get_create_delete(void)
{
	struct sk_ls_reserve *skel;
	int fd = -1, err;
	__u32 len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create,
					   cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	/* First getsockopt triggers get+CREATE */
	skel->bss->test_op = 0; /* OP_CREATE */
	len = sizeof(val);
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_create");
	ASSERT_EQ(skel->bss->result, 1, "create_ok");

	/* Second call should find existing storage */
	skel->bss->test_op = 1; /* OP_GET */
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_get");
	ASSERT_EQ(skel->bss->result, 1, "get_ok");
	ASSERT_EQ(skel->bss->val_a, 2, "val_a_after_two_gets");

	/* Delete */
	skel->bss->test_op = 2; /* OP_DELETE */
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_delete");
	ASSERT_EQ(skel->bss->delete_result, 0, "delete_ok");

	/* Get without CREATE after delete should return NULL */
	skel->bss->test_op = 1; /* OP_GET */
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_get_after_delete");
	ASSERT_EQ(skel->bss->result, 0, "get_after_delete_null");

done:
	if (fd != -1)
		close(fd);
	sk_ls_reserve__destroy(skel);
}

void test_ns_sk_ls_reserve(void)
{
	cgroup_fd = test__join_cgroup("/sk_ls_reserve");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup"))
		return;

	if (test__start_subtest("get_create_delete"))
		test_get_create_delete();

	close(cgroup_fd);
}
