// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>
#include <bpf/btf.h>
#include "cgroup_helpers.h"
#include "bpf_tcp_ops.skel.h"

#define CGROUP_PATH	"/bpf_tcp_ops"
#define TEST_NETNS	"bpf_tcp_ops"

static __s32 get_bpf_tcp_ops_type_id(void)
{
	struct btf *vmlinux_btf;
	__s32 type_id;

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "load_vmlinux_btf"))
		return -1;

	type_id = btf__find_by_name_kind(vmlinux_btf, "bpf_tcp_ops", BTF_KIND_STRUCT);
	btf__free(vmlinux_btf);

	ASSERT_GT(type_id, 0, "find_bpf_tcp_ops");
	return type_id;
}

static void reset_order(struct bpf_tcp_ops *skel)
{
	memset(skel->bss->listen_order, 0, sizeof(skel->bss->listen_order));
	memset(skel->bss->connect_order, 0, sizeof(skel->bss->connect_order));
	skel->bss->listen_cnt = 0;
	skel->bss->connect_cnt = 0;
}

static void do_listen_connect(int family)
{
	const char *addr = family == AF_INET ? "127.0.0.1" : "::1";
	int server_fd, client_fd;

	server_fd = start_server(family, SOCK_STREAM, addr, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (ASSERT_OK_FD(client_fd, "connect_to_fd"))
		close(client_fd);

	close(server_fd);
}

/*
 * Attach ops1 and ops2 normally (in that order), then ops3 with
 * BPF_F_PREORDER. Expected execution order: [3, 1, 2] — ops3 runs
 * first despite being attached last, ops1 before ops2 by attach order.
 */
static void test_order(int cgroup_fd, struct bpf_tcp_ops *skel, int family)
{
	LIBBPF_OPTS(bpf_cgroup_opts, preorder_opts, .flags = BPF_F_PREORDER);
	struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL;

	link1 = bpf_map__attach_cgroup_opts(skel->maps.tcp_ops1, cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link1, "attach_ops1"))
		goto done;

	link2 = bpf_map__attach_cgroup_opts(skel->maps.tcp_ops2, cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link2, "attach_ops2"))
		goto done;

	link3 = bpf_map__attach_cgroup_opts(skel->maps.tcp_ops3, cgroup_fd,
					    &preorder_opts);
	if (!ASSERT_OK_PTR(link3, "attach_ops3_preorder"))
		goto done;

	reset_order(skel);
	do_listen_connect(family);

	ASSERT_EQ(skel->bss->listen_cnt, 3, "listen_cnt");
	ASSERT_EQ(skel->bss->listen_order[0], 3, "listen_order[0]");
	ASSERT_EQ(skel->bss->listen_order[1], 1, "listen_order[1]");
	ASSERT_EQ(skel->bss->listen_order[2], 2, "listen_order[2]");

	ASSERT_EQ(skel->bss->connect_cnt, 3, "connect_cnt");
	ASSERT_EQ(skel->bss->connect_order[0], 3, "connect_order[0]");
	ASSERT_EQ(skel->bss->connect_order[1], 1, "connect_order[1]");
	ASSERT_EQ(skel->bss->connect_order[2], 2, "connect_order[2]");

done:
	bpf_link__destroy(link3);
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
}

static void test_query(int cgroup_fd, struct bpf_tcp_ops *skel)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	LIBBPF_OPTS(bpf_prog_query_opts, query_opts);
	struct bpf_link *link1 = NULL, *link2 = NULL;
	__u32 map1_id, map2_id, map_ids[2] = {};
	__s32 type_id;

	type_id = get_bpf_tcp_ops_type_id();
	if (type_id <= 0)
		return;

	bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.tcp_ops1), &info, &info_len);
	map1_id = info.id;

	bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.tcp_ops2), &info, &info_len);
	map2_id = info.id;

	link1 = bpf_map__attach_cgroup_opts(skel->maps.tcp_ops1, cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link1, "attach_ops1"))
		goto done;

	link2 = bpf_map__attach_cgroup_opts(skel->maps.tcp_ops2, cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link2, "attach_ops2"))
		goto done;

	/* query effective: expect 2 entries in attachment order */
	query_opts.type_id = type_id;
	query_opts.prog_ids = map_ids;
	query_opts.count = ARRAY_SIZE(map_ids);
	query_opts.query_flags = BPF_F_QUERY_EFFECTIVE;
	ASSERT_OK(bpf_prog_query_opts(cgroup_fd, BPF_STRUCT_OPS, &query_opts),
		  "query_effective");
	ASSERT_EQ(query_opts.count, 2, "query_effective_count");
	ASSERT_EQ(map_ids[0], map1_id, "map_ids[0]");
	ASSERT_EQ(map_ids[1], map2_id, "map_ids[1]");

	/* query attached (non-effective): expect 2 entries */
	memset(map_ids, 0, sizeof(map_ids));
	query_opts.query_flags = 0;
	query_opts.count = ARRAY_SIZE(map_ids);
	ASSERT_OK(bpf_prog_query_opts(cgroup_fd, BPF_STRUCT_OPS, &query_opts),
		  "query_attached");
	ASSERT_EQ(query_opts.count, 2, "query_attached_count");
	ASSERT_EQ(map_ids[0], map1_id, "attached_map_ids[0]");
	ASSERT_EQ(map_ids[1], map2_id, "attached_map_ids[1]");

done:
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
}

static void run_query_subtest(void)
{
	struct bpf_tcp_ops *skel = NULL;
	struct netns_obj *ns = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	ns = netns_new(TEST_NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto done;

	skel = bpf_tcp_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto done;

	test_query(cgroup_fd, skel);

done:
	bpf_tcp_ops__destroy(skel);
	netns_free(ns);
	close(cgroup_fd);
}

static void run_order_subtest(void)
{
	struct bpf_tcp_ops *skel = NULL;
	struct netns_obj *ns = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	ns = netns_new(TEST_NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto done;

	skel = bpf_tcp_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto done;

	test_order(cgroup_fd, skel, AF_INET);
	test_order(cgroup_fd, skel, AF_INET6);

done:
	bpf_tcp_ops__destroy(skel);
	netns_free(ns);
	close(cgroup_fd);
}

void test_bpf_tcp_ops(void)
{
	if (test__start_subtest("query"))
		run_query_subtest();
	if (test__start_subtest("order"))
		run_order_subtest();
}
