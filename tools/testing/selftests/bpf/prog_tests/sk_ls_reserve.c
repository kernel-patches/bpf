// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "sk_ls_reserve.skel.h"

static int cgroup_fd;

static void test_get_create_delete(void)
{
	struct sk_ls_reserve *skel;
	int fd = -1, err;
	socklen_t len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	len = sizeof(val);

	skel->bss->test_op = 0;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_create");
	ASSERT_EQ(skel->bss->result, 1, "create_ok");

	skel->bss->test_op = 1;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_get");
	ASSERT_EQ(skel->bss->result, 1, "get_ok");
	ASSERT_EQ(skel->bss->val_a, 2, "val_a_after_two_gets");

	skel->bss->test_op = 2;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_delete");
	ASSERT_EQ(skel->bss->delete_result, 0, "delete_ok");

	skel->bss->test_op = 1;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "getsockopt_get_after_delete");
	ASSERT_EQ(skel->bss->result, 0, "get_after_delete_null");

done:
	if (fd != -1)
		close(fd);
	sk_ls_reserve__destroy(skel);
}

static void test_multiple_maps(void)
{
	struct sk_ls_reserve *skel;
	int fd = -1, err;
	socklen_t len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	len = sizeof(val);

	skel->bss->test_op = 3;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "create_both");
	ASSERT_EQ(skel->bss->result, 1, "map1_create_ok");
	ASSERT_EQ(skel->bss->result2, 1, "map2_create_ok");
	ASSERT_EQ(skel->bss->val_a, 1, "map1_val_a");
	ASSERT_EQ(skel->bss->val2_a, 10, "map2_val_a");

	skel->bss->test_op = 4;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_both");
	ASSERT_EQ(skel->bss->result, 1, "map1_get_ok");
	ASSERT_EQ(skel->bss->result2, 1, "map2_get_ok");

	skel->bss->test_op = 5;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "delete_map2");
	ASSERT_EQ(skel->bss->delete_result, 0, "map2_delete_ok");

	skel->bss->test_op = 4;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_after_partial_delete");
	ASSERT_EQ(skel->bss->result, 1, "map1_still_exists");
	ASSERT_EQ(skel->bss->result2, 0, "map2_gone");

done:
	if (fd != -1)
		close(fd);
	sk_ls_reserve__destroy(skel);
}

static void test_create_with_value(void)
{
	struct sk_ls_reserve *skel;
	int fd = -1, err;
	socklen_t len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	len = sizeof(val);

	skel->bss->test_op = 6;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "create_with_val");
	ASSERT_EQ(skel->bss->result, 1, "create_val_ok");
	ASSERT_EQ(skel->bss->val_a, 100, "init_val_a");

	skel->bss->test_op = 7;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "create_again");
	ASSERT_EQ(skel->bss->result, 1, "create_again_ok");
	ASSERT_EQ(skel->bss->val_a, 101, "val_not_reset");

done:
	if (fd != -1)
		close(fd);
	sk_ls_reserve__destroy(skel);
}

static void test_delete_nonexistent(void)
{
	struct sk_ls_reserve *skel;
	int fd = -1, err;
	socklen_t len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	len = sizeof(val);

	skel->bss->test_op = 8;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "delete_nonexist");
	ASSERT_EQ(skel->bss->delete_result, -ENOENT, "enoent");

done:
	if (fd != -1)
		close(fd);
	sk_ls_reserve__destroy(skel);
}

static void test_multiple_sockets(void)
{
	struct sk_ls_reserve *skel;
	int fd1 = -1, fd2 = -1, err;
	socklen_t len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd1 = socket(AF_INET6, SOCK_STREAM, 0);
	fd2 = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd1, "socket1") || !ASSERT_OK_FD(fd2, "socket2"))
		goto done;

	len = sizeof(val);

	skel->bss->test_op = 0;
	err = getsockopt(fd1, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "create_sock1");

	skel->bss->test_op = 0;
	err = getsockopt(fd2, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "create_sock2");

	skel->bss->test_op = 1;
	err = getsockopt(fd1, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_sock1");
	ASSERT_EQ(skel->bss->val_a, 2, "sock1_val_a");

	skel->bss->test_op = 1;
	err = getsockopt(fd2, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_sock2");
	ASSERT_EQ(skel->bss->val_a, 2, "sock2_val_a");

	skel->bss->test_op = 2;
	err = getsockopt(fd1, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "delete_sock1");

	skel->bss->test_op = 1;
	err = getsockopt(fd1, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_sock1_deleted");
	ASSERT_EQ(skel->bss->result, 0, "sock1_null");

	skel->bss->test_op = 1;
	err = getsockopt(fd2, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_sock2_unaffected");
	ASSERT_EQ(skel->bss->result, 1, "sock2_ok");

done:
	if (fd1 != -1)
		close(fd1);
	if (fd2 != -1)
		close(fd2);
	sk_ls_reserve__destroy(skel);
}

static void test_recreate_after_delete(void)
{
	struct sk_ls_reserve *skel;
	int fd = -1, err;
	socklen_t len;
	int val;

	skel = sk_ls_reserve__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->links.get_create =
		bpf_program__attach_cgroup(skel->progs.get_create, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.get_create, "attach"))
		goto done;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto done;

	len = sizeof(val);

	skel->bss->test_op = 0;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "create");

	skel->bss->test_op = 2;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "delete");
	ASSERT_EQ(skel->bss->delete_result, 0, "delete_ok");

	skel->bss->test_op = 0;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "recreate");
	ASSERT_EQ(skel->bss->result, 1, "recreate_ok");

	skel->bss->test_op = 1;
	err = getsockopt(fd, 0xdead, 0xbeef, &val, &len);
	ASSERT_OK(err, "get_after_recreate");
	ASSERT_EQ(skel->bss->val_a, 2, "val_a_fresh");

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
	if (test__start_subtest("multiple_maps"))
		test_multiple_maps();
	if (test__start_subtest("create_with_value"))
		test_create_with_value();
	if (test__start_subtest("delete_nonexistent"))
		test_delete_nonexistent();
	if (test__start_subtest("multiple_sockets"))
		test_multiple_sockets();
	if (test__start_subtest("recreate_after_delete"))
		test_recreate_after_delete();

	close(cgroup_fd);
}
