// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/bpf_endian.h>

#include "sock_destroy_prog.skel.h"
#include "sock_destroy_prog_fail.skel.h"
#include "network_helpers.h"

#define TEST_NS "sock_destroy_netns"

static void start_iter_sockets(struct bpf_program *prog, struct bpf_map *map)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link;
	char buf[50] = {};
	int iter_fd, len;

	if (map)
		linfo.map.map_fd = bpf_map__fd(map);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(prog, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create_iter"))
		goto free_link;

	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	ASSERT_GE(len, 0, "read");

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
}

static int insert_socket(struct bpf_map *socks, int fd, __u32 key)
{
	int map_fd = bpf_map__fd(socks);
	__s64 sfd = fd;
	int ret;

	ret = bpf_map_update_elem(map_fd, &key, &sfd, BPF_NOEXIST);
	if (!ASSERT_OK(ret, "map_update"))
		return -1;

	return 0;
}

static void test_tcp_client(struct sock_destroy_prog *skel,
			    struct bpf_program *prog,
			    struct bpf_map *socks)
{
	int serv = -1, clien = -1, accept_serv = -1, n;

	serv = start_server(AF_INET6, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	clien = connect_to_fd(serv, 0);
	if (!ASSERT_GE(clien, 0, "connect_to_fd"))
		goto cleanup;

	accept_serv = accept(serv, NULL, NULL);
	if (!ASSERT_GE(accept_serv, 0, "serv accept"))
		goto cleanup;

	n = send(clien, "t", 1, 0);
	if (!ASSERT_EQ(n, 1, "client send"))
		goto cleanup;

	if (socks) {
		if (!ASSERT_OK(insert_socket(socks, clien, 0),
			       "insert_socket"))
			goto cleanup;
		if (!ASSERT_OK(insert_socket(socks, serv, 1),
			       "insert_socket"))
			goto cleanup;
	}

	/* Run iterator program that destroys connected client sockets. */
	start_iter_sockets(prog, socks);

	n = send(clien, "t", 1, 0);
	if (!ASSERT_LT(n, 0, "client_send on destroyed socket"))
		goto cleanup;
	ASSERT_EQ(errno, ECONNABORTED, "error code on destroyed socket");

cleanup:
	if (clien != -1)
		close(clien);
	if (accept_serv != -1)
		close(accept_serv);
	if (serv != -1)
		close(serv);
}

static void test_tcp_server(struct sock_destroy_prog *skel,
			    struct bpf_program *prog,
			    struct bpf_map *socks)
{
	int serv = -1, clien = -1, accept_serv = -1, n, serv_port;

	serv = start_server(AF_INET6, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;
	serv_port = get_socket_local_port(serv);
	if (!ASSERT_GE(serv_port, 0, "get_sock_local_port"))
		goto cleanup;
	skel->bss->serv_port = (__be16) serv_port;

	clien = connect_to_fd(serv, 0);
	if (!ASSERT_GE(clien, 0, "connect_to_fd"))
		goto cleanup;

	accept_serv = accept(serv, NULL, NULL);
	if (!ASSERT_GE(accept_serv, 0, "serv accept"))
		goto cleanup;

	n = send(clien, "t", 1, 0);
	if (!ASSERT_EQ(n, 1, "client send"))
		goto cleanup;

	if (socks) {
		if (!ASSERT_OK(insert_socket(socks, clien, 0),
			       "insert_socket"))
			goto cleanup;
		if (!ASSERT_OK(insert_socket(socks, accept_serv, 1),
			       "insert_socket"))
			goto cleanup;
	}

	/* Run iterator program that destroys server sockets. */
	start_iter_sockets(prog, socks);

	n = send(clien, "t", 1, 0);
	if (!ASSERT_LT(n, 0, "client_send on destroyed socket"))
		goto cleanup;
	ASSERT_EQ(errno, ECONNRESET, "error code on destroyed socket");

cleanup:
	if (clien != -1)
		close(clien);
	if (accept_serv != -1)
		close(accept_serv);
	if (serv != -1)
		close(serv);
}

static void test_udp_client(struct sock_destroy_prog *skel,
			    struct bpf_program *prog,
			    struct bpf_map *socks)
{
	int serv = -1, clien = -1, n = 0;

	serv = start_server(AF_INET6, SOCK_DGRAM, NULL, 0, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	clien = connect_to_fd(serv, 0);
	if (!ASSERT_GE(clien, 0, "connect_to_fd"))
		goto cleanup;

	n = send(clien, "t", 1, 0);
	if (!ASSERT_EQ(n, 1, "client send"))
		goto cleanup;

	if (socks) {
		if (!ASSERT_OK(insert_socket(socks, clien, 0),
			       "insert_socket"))
			goto cleanup;
		if (!ASSERT_OK(insert_socket(socks, serv, 1),
			       "insert_socket"))
			goto cleanup;
	}

	/* Run iterator program that destroys sockets. */
	start_iter_sockets(prog, socks);

	n = send(clien, "t", 1, 0);
	if (!ASSERT_LT(n, 0, "client_send on destroyed socket"))
		goto cleanup;
	/* UDP sockets have an overriding error code after they are disconnected,
	 * so we don't check for ECONNABORTED error code.
	 */

cleanup:
	if (clien != -1)
		close(clien);
	if (serv != -1)
		close(serv);
}

static void test_udp_server(struct sock_destroy_prog *skel,
			    struct bpf_program *prog,
			    struct bpf_map *socks)
{
	int *listen_fds = NULL, n, i, serv_port;
	unsigned int num_listens = 5;
	char buf[1];
	__u32 key;

	/* Start reuseport servers. */
	listen_fds = start_reuseport_server(AF_INET6, SOCK_DGRAM,
					    "::1", 0, 0, num_listens);
	if (!ASSERT_OK_PTR(listen_fds, "start_reuseport_server"))
		goto cleanup;
	serv_port = get_socket_local_port(listen_fds[0]);
	if (!ASSERT_GE(serv_port, 0, "get_sock_local_port"))
		goto cleanup;
	skel->bss->serv_port = (__be16) serv_port;

	if (socks)
		for (key = 0; key < num_listens; key++)
			if (!ASSERT_OK(insert_socket(socks, listen_fds[key],
						     key),
				       "insert_socket"))
				goto cleanup;

	/* Run iterator program that destroys server sockets. */
	start_iter_sockets(prog, socks);

	for (i = 0; i < num_listens; ++i) {
		n = read(listen_fds[i], buf, sizeof(buf));
		if (!ASSERT_EQ(n, -1, "read") ||
		    !ASSERT_EQ(errno, ECONNABORTED, "error code on destroyed socket"))
			break;
	}
	ASSERT_EQ(i, num_listens, "server socket");

cleanup:
	free_fds(listen_fds, num_listens);
}

void test_sock_destroy(void)
{
	struct sock_destroy_prog *skel;
	struct nstoken *nstoken = NULL;
	int cgroup_fd;

	skel = sock_destroy_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	cgroup_fd = test__join_cgroup("/sock_destroy");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto cleanup;

	skel->links.sock_connect = bpf_program__attach_cgroup(
		skel->progs.sock_connect, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.sock_connect, "prog_attach"))
		goto cleanup;

	SYS(cleanup, "ip netns add %s", TEST_NS);
	SYS(cleanup, "ip -net %s link set dev lo up", TEST_NS);

	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto cleanup;

	if (test__start_subtest("tcp_client")) {
		test_tcp_client(skel, skel->progs.iter_tcp6_client, NULL);
		test_tcp_client(skel, skel->progs.iter_sockmap_client,
				skel->maps.sock_map);
		test_tcp_client(skel, skel->progs.iter_sockmap_client,
				skel->maps.sock_hash);
	}
	if (test__start_subtest("tcp_server")) {
		test_tcp_server(skel, skel->progs.iter_tcp6_server, NULL);
		test_tcp_server(skel, skel->progs.iter_sockmap_server,
				skel->maps.sock_map);
		test_tcp_server(skel, skel->progs.iter_sockmap_server,
				skel->maps.sock_hash);
	}
	if (test__start_subtest("udp_client")) {
		test_udp_client(skel, skel->progs.iter_udp6_client, NULL);
		test_udp_client(skel, skel->progs.iter_sockmap_client,
				skel->maps.sock_map);
		test_udp_client(skel, skel->progs.iter_sockmap_client,
				skel->maps.sock_hash);
	}
	if (test__start_subtest("udp_server")) {
		test_udp_server(skel, skel->progs.iter_udp6_server, NULL);
		test_udp_server(skel, skel->progs.iter_sockmap_server,
				skel->maps.sock_map);
		test_udp_server(skel, skel->progs.iter_sockmap_server,
				skel->maps.sock_hash);
	}

	RUN_TESTS(sock_destroy_prog_fail);

cleanup:
	if (nstoken)
		close_netns(nstoken);
	SYS_NOFAIL("ip netns del " TEST_NS);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	sock_destroy_prog__destroy(skel);
}
