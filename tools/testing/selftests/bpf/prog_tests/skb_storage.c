// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include <test_progs.h>
#include <network_helpers.h>
#include "skb_storage.skel.h"

#define CGROUP_PATH "/skb_storage"
#define DUMMY_DEV "dum0"
#define IFINDEX_LO 1
#define MAGIC_VALUE 0xdeadbeef
#define TEST_PORT 4242

static int send_udp_packet(__be16 port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int fd, ret = -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	ret = sendto(fd, "x", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		goto out;

	ret = 0;
out:
	close(fd);
	return ret;
}

static int recv_udp_packet(int server_fd)
{
	char buf[64];
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	return recvfrom(server_fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&addr, &len);
}

static void test_skb_storage_ops(struct skb_storage *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.skb_storage_ops_test),
				     &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(skel->bss->test_result, 0, "test_result");
}

static void test_tc_clone_redirect(struct skb_storage *skel)
{
	const __be16 test_port = htons(TEST_PORT);
	struct bpf_link *dummy_link = NULL;
	struct bpf_link *lo_link = NULL;
	struct netns_obj *netns;
	int dummy_ifindex;

	netns = netns_new(__func__, true);
	if (!ASSERT_OK_PTR(netns, "netns_new"))
		goto cleanup;

	SYS(cleanup, "ip link add " DUMMY_DEV " type dummy");
	SYS(cleanup, "ip link set " DUMMY_DEV " up");

	dummy_ifindex = if_nametoindex(DUMMY_DEV);
	if (!ASSERT_GT(dummy_ifindex, 0, "dummy_ifindex"))
		goto cleanup;

	skel->bss->target_port = test_port;
	skel->bss->redirect_ifindex = dummy_ifindex;

	lo_link = bpf_program__attach_tcx(skel->progs.tc_clone_redirect_store,
					  IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(lo_link, "attach_ingress"))
		goto cleanup;

	dummy_link = bpf_program__attach_tcx(skel->progs.tc_clone_redirect_load,
					     dummy_ifindex, NULL);
	if (!ASSERT_OK_PTR(dummy_link, "attach_egress"))
		goto cleanup;

	skel->bss->store_seen = 0;
	skel->bss->redir_seen = 0;
	skel->bss->load_seen = 0;
	skel->bss->load_value = 0;

	if (!ASSERT_OK(send_udp_packet(test_port), "send_udp"))
		goto cleanup;

	ASSERT_EQ(skel->bss->store_seen, 1, "store_seen");
	ASSERT_EQ(skel->bss->redir_seen, 1, "redir_seen");
	ASSERT_EQ(skel->bss->load_seen, 0, "load_seen");
	ASSERT_EQ(skel->bss->load_value, 0, "load_value");

cleanup:
	bpf_link__destroy(dummy_link);
	bpf_link__destroy(lo_link);
	netns_free(netns);
}

static void test_tc_ingress_to_cgrp_ingress(struct skb_storage *skel)
{
	struct bpf_link *tc_link = NULL;
	struct bpf_link *cg_link = NULL;
	int cgroup_fd = -1;
	int server_fd = -1;
	__be16 port;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	server_fd = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	skel->bss->target_port = port;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store,
					  IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tc"))
		goto cleanup;

	cg_link = bpf_program__attach_cgroup(skel->progs.cgrp_ingress_load,
					     cgroup_fd);
	if (!ASSERT_OK_PTR(cg_link, "attach_cgroup"))
		goto cleanup;

	skel->bss->store_seen = 0;
	skel->bss->load_seen = 0;
	skel->bss->load_value = 0;

	if (!ASSERT_OK(send_udp_packet(port), "send_udp"))
		goto cleanup;

	if (!ASSERT_GE(recv_udp_packet(server_fd), 0, "recv_udp"))
		goto cleanup;

	ASSERT_EQ(skel->bss->store_seen, 1, "store_seen");
	ASSERT_EQ(skel->bss->load_seen, 1, "load_seen");
	ASSERT_EQ(skel->bss->load_value, MAGIC_VALUE, "load_value");

cleanup:
	bpf_link__destroy(cg_link);
	bpf_link__destroy(tc_link);
	if (server_fd >= 0)
		close(server_fd);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void test_tc_ingress_to_sk_filter(struct skb_storage *skel)
{
	struct bpf_link *tc_link = NULL;
	int server_fd = -1;
	int filter_fd = -1;
	__be16 port;
	int ret;

	server_fd = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	skel->bss->target_port = port;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store,
					  IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tcx"))
		goto cleanup;

	filter_fd = bpf_program__fd(skel->progs.sk_filter_load);
	if (!ASSERT_GE(filter_fd, 0, "get_prog_fd"))
		goto cleanup;

	ret = setsockopt(server_fd, SOL_SOCKET, SO_ATTACH_BPF,
			 &filter_fd, sizeof(filter_fd));
	if (!ASSERT_OK(ret, "attach_socket_filter"))
		goto cleanup;

	skel->bss->store_seen = 0;
	skel->bss->load_seen = 0;
	skel->bss->load_value = 0;

	if (!ASSERT_OK(send_udp_packet(port), "send_udp"))
		goto cleanup;

	if (!ASSERT_GE(recv_udp_packet(server_fd), 0, "recv_udp"))
		goto cleanup;

	ASSERT_EQ(skel->bss->store_seen, 1, "store_seen");
	ASSERT_EQ(skel->bss->load_seen, 1, "load_seen");
	ASSERT_EQ(skel->bss->load_value, MAGIC_VALUE, "load_value");

cleanup:
	bpf_link__destroy(tc_link);
	if (server_fd >= 0)
		close(server_fd);
}

static void test_cgrp_egress_to_tp_kfree_skb(struct skb_storage *skel)
{
	struct bpf_link *cg_link = NULL;
	struct bpf_link *tp_link = NULL;
	struct netns_obj *netns = NULL;
	int cgroup_fd = -1;
	__be16 port;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	netns = netns_new(__func__, true);
	if (!ASSERT_OK_PTR(netns, "netns_new"))
		goto cleanup;

	port = htons(TEST_PORT);
	skel->bss->target_port = port;

	cg_link = bpf_program__attach_cgroup(skel->progs.cgrp_egress_store,
					     cgroup_fd);
	if (!ASSERT_OK_PTR(cg_link, "attach_cgroup"))
		goto cleanup;

	tp_link = bpf_program__attach_trace(skel->progs.tp_kfree_skb_load);
	if (!ASSERT_OK_PTR(tp_link, "attach_tp"))
		goto cleanup;

	skel->bss->store_seen = 0;
	skel->bss->load_seen = 0;
	skel->bss->load_value = 0;

	SYS(cleanup, "tc qdisc add dev lo root handle 1:0 blackhole");

	if (!ASSERT_OK(send_udp_packet(port), "send_udp"))
		goto cleanup;

	ASSERT_EQ(skel->bss->store_seen, 1, "store_seen");
	ASSERT_EQ(skel->bss->load_seen, 1, "load_seen");
	ASSERT_EQ(skel->bss->load_value, MAGIC_VALUE, "load_value");

cleanup:
	bpf_link__destroy(tp_link);
	bpf_link__destroy(cg_link);
	netns_free(netns);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void test_tc_ingress_to_lsm_inet_conn_estab(struct skb_storage *skel)
{
	struct bpf_link *lsm_link = NULL;
	struct bpf_link *tc_link = NULL;
	int server_fd = -1;
	int client_fd = -1;
	int conn_fd = -1;
	__be16 port;

	server_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	skel->bss->target_port = port;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store, IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tcx"))
		goto cleanup;

	lsm_link = bpf_program__attach_lsm(skel->progs.lsm_inet_conn_estab_load);
	if (!ASSERT_OK_PTR(lsm_link, "attach_lsm"))
		goto cleanup;

	skel->bss->store_seen = 0;
	skel->bss->load_seen = 0;
	skel->bss->load_value = 0;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect"))
		goto cleanup;

	conn_fd = accept(server_fd, NULL, NULL);
	if (!ASSERT_GE(conn_fd, 0, "accept"))
		goto cleanup;
	close(conn_fd);

	ASSERT_GT(skel->bss->store_seen, 0, "store_seen");
	ASSERT_GT(skel->bss->load_seen, 0, "load_seen");
	ASSERT_EQ(skel->bss->load_value, MAGIC_VALUE, "load_value");

cleanup:
	bpf_link__destroy(lsm_link);
	bpf_link__destroy(tc_link);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
}

static void test_tc_ingress_to_skops_passive_estab(struct skb_storage *skel)
{
	struct bpf_link *cg_link = NULL;
	struct bpf_link *tc_link = NULL;
	int cgroup_fd = -1;
	int server_fd = -1;
	int client_fd = -1;
	int conn_fd = -1;
	__be16 port;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	server_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	skel->bss->target_port = port;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store, IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tcx"))
		goto cleanup;

	cg_link = bpf_program__attach_cgroup(skel->progs.skops_passive_estab_load, cgroup_fd);
	if (!ASSERT_OK_PTR(cg_link, "attach_cgroup"))
		goto cleanup;

	skel->bss->store_seen = 0;
	skel->bss->load_seen = 0;
	skel->bss->load_value = 0;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect"))
		goto cleanup;

	conn_fd = accept(server_fd, NULL, NULL);
	if (!ASSERT_GE(conn_fd, 0, "accept"))
		goto cleanup;
	close(conn_fd);

	ASSERT_GT(skel->bss->store_seen, 0, "store_seen");
	ASSERT_GT(skel->bss->load_seen, 0, "load_seen");
	ASSERT_EQ(skel->bss->load_value, MAGIC_VALUE, "load_value");

cleanup:
	bpf_link__destroy(cg_link);
	bpf_link__destroy(tc_link);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

void test_skb_storage(void)
{
	struct skb_storage *skel;

	skel = skb_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	if (test__start_subtest("skb_storage_ops"))
		test_skb_storage_ops(skel);
	if (test__start_subtest("tc_clone_redirect"))
		test_tc_clone_redirect(skel);
	if (test__start_subtest("tc_ingress_to_cgrp_ingress"))
		test_tc_ingress_to_cgrp_ingress(skel);
	if (test__start_subtest("tc_ingress_to_sk_filter"))
		test_tc_ingress_to_sk_filter(skel);
	if (test__start_subtest("cgrp_egress_to_tp_kfree_skb"))
		test_cgrp_egress_to_tp_kfree_skb(skel);
	if (test__start_subtest("tc_ingress_to_lsm_inet_conn_estab"))
		test_tc_ingress_to_lsm_inet_conn_estab(skel);
	if (test__start_subtest("tc_ingress_to_skops_passive_estab"))
		test_tc_ingress_to_skops_passive_estab(skel);

	skb_storage__destroy(skel);
}
