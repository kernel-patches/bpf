// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare
#include <error.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

#include "test_progs.h"
#include "test_skmsg_load_helpers.skel.h"
#include "test_sockmap_update.skel.h"
#include "test_sockmap_invalid_update.skel.h"
#include "test_sockmap_skb_verdict_attach.skel.h"
#include "test_sockmap_progs_query.skel.h"
#include "test_sockmap_pass_prog.skel.h"
#include "test_sockmap_drop_prog.skel.h"
#include "test_sockmap_change_tail.skel.h"
#include "bpf_iter_sockmap.skel.h"

#include "sockmap_helpers.h"
#include "network_helpers.h"

#define TCP_REPAIR		19	/* TCP sock is under repair right now */

#define TCP_REPAIR_ON		1
#define TCP_REPAIR_OFF_NO_WP	-1	/* Turn off without window probes */

static int connected_socket_v4(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(80),
		.sin_addr = { inet_addr("127.0.0.1") },
	};
	socklen_t len = sizeof(addr);
	int s, repair, err;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_GE(s, 0, "socket"))
		goto error;

	repair = TCP_REPAIR_ON;
	err = setsockopt(s, SOL_TCP, TCP_REPAIR, &repair, sizeof(repair));
	if (!ASSERT_OK(err, "setsockopt(TCP_REPAIR)"))
		goto error;

	err = connect(s, (struct sockaddr *)&addr, len);
	if (!ASSERT_OK(err, "connect"))
		goto error;

	repair = TCP_REPAIR_OFF_NO_WP;
	err = setsockopt(s, SOL_TCP, TCP_REPAIR, &repair, sizeof(repair));
	if (!ASSERT_OK(err, "setsockopt(TCP_REPAIR)"))
		goto error;

	return s;
error:
	perror(__func__);
	close(s);
	return -1;
}

static void compare_cookies(struct bpf_map *src, struct bpf_map *dst)
{
	__u32 i, max_entries = bpf_map__max_entries(src);
	int err, src_fd, dst_fd;

	src_fd = bpf_map__fd(src);
	dst_fd = bpf_map__fd(dst);

	for (i = 0; i < max_entries; i++) {
		__u64 src_cookie, dst_cookie;

		err = bpf_map_lookup_elem(src_fd, &i, &src_cookie);
		if (err && errno == ENOENT) {
			err = bpf_map_lookup_elem(dst_fd, &i, &dst_cookie);
			ASSERT_ERR(err, "map_lookup_elem(dst)");
			ASSERT_EQ(errno, ENOENT, "map_lookup_elem(dst)");
			continue;
		}
		if (!ASSERT_OK(err, "lookup_elem(src)"))
			continue;

		err = bpf_map_lookup_elem(dst_fd, &i, &dst_cookie);
		if (!ASSERT_OK(err, "lookup_elem(dst)"))
			continue;

		ASSERT_EQ(dst_cookie, src_cookie, "cookie mismatch");
	}
}

/* Create a map, populate it with one socket, and free the map. */
static void test_sockmap_create_update_free(enum bpf_map_type map_type)
{
	const int zero = 0;
	int s, map, err;

	s = connected_socket_v4();
	if (!ASSERT_GE(s, 0, "connected_socket_v4"))
		return;

	map = bpf_map_create(map_type, NULL, sizeof(int), sizeof(int), 1, NULL);
	if (!ASSERT_GE(map, 0, "bpf_map_create"))
		goto out;

	err = bpf_map_update_elem(map, &zero, &s, BPF_NOEXIST);
	if (!ASSERT_OK(err, "bpf_map_update"))
		goto out;

out:
	close(map);
	close(s);
}

static void test_sockmap_vsock_delete_on_close(void)
{
	int map, c, p, err, zero = 0;

	map = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, NULL, sizeof(int),
			     sizeof(int), 1, NULL);
	if (!ASSERT_OK_FD(map, "bpf_map_create"))
		return;

	err = create_pair(AF_VSOCK, SOCK_STREAM, &c, &p);
	if (!ASSERT_OK(err, "create_pair"))
		goto close_map;

	if (xbpf_map_update_elem(map, &zero, &c, BPF_NOEXIST))
		goto close_socks;

	xclose(c);
	xclose(p);

	err = create_pair(AF_VSOCK, SOCK_STREAM, &c, &p);
	if (!ASSERT_OK(err, "create_pair"))
		goto close_map;

	err = bpf_map_update_elem(map, &zero, &c, BPF_NOEXIST);
	ASSERT_OK(err, "after close(), bpf_map_update");

close_socks:
	xclose(c);
	xclose(p);
close_map:
	xclose(map);
}

static void test_skmsg_helpers(enum bpf_map_type map_type)
{
	struct test_skmsg_load_helpers *skel;
	int err, map, verdict;

	skel = test_skmsg_load_helpers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_skmsg_load_helpers__open_and_load"))
		return;

	verdict = bpf_program__fd(skel->progs.prog_msg_verdict);
	map = bpf_map__fd(skel->maps.sock_map);

	err = bpf_prog_attach(verdict, map, BPF_SK_MSG_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	err = bpf_prog_detach2(verdict, map, BPF_SK_MSG_VERDICT);
	if (!ASSERT_OK(err, "bpf_prog_detach2"))
		goto out;
out:
	test_skmsg_load_helpers__destroy(skel);
}

static void test_skmsg_helpers_with_link(enum bpf_map_type map_type)
{
	struct bpf_program *prog, *prog_clone, *prog_clone2;
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, opts);
	struct test_skmsg_load_helpers *skel;
	struct bpf_link *link, *link2;
	int err, map;

	skel = test_skmsg_load_helpers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_skmsg_load_helpers__open_and_load"))
		return;

	prog = skel->progs.prog_msg_verdict;
	prog_clone = skel->progs.prog_msg_verdict_clone;
	prog_clone2 = skel->progs.prog_msg_verdict_clone2;
	map = bpf_map__fd(skel->maps.sock_map);

	link = bpf_program__attach_sockmap(prog, map);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_sockmap"))
		goto out;

	/* Fail since bpf_link for the same prog has been created. */
	err = bpf_prog_attach(bpf_program__fd(prog), map, BPF_SK_MSG_VERDICT, 0);
	if (!ASSERT_ERR(err, "bpf_prog_attach"))
		goto out;

	/* Fail since bpf_link for the same prog type has been created. */
	link2 = bpf_program__attach_sockmap(prog_clone, map);
	if (!ASSERT_ERR_PTR(link2, "bpf_program__attach_sockmap")) {
		bpf_link__detach(link2);
		goto out;
	}

	err = bpf_link__update_program(link, prog_clone);
	if (!ASSERT_OK(err, "bpf_link__update_program"))
		goto out;

	/* Fail since a prog with different type attempts to do update. */
	err = bpf_link__update_program(link, skel->progs.prog_skb_verdict);
	if (!ASSERT_ERR(err, "bpf_link__update_program"))
		goto out;

	/* Fail since the old prog does not match the one in the kernel. */
	opts.old_prog_fd = bpf_program__fd(prog_clone2);
	opts.flags = BPF_F_REPLACE;
	err = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog), &opts);
	if (!ASSERT_ERR(err, "bpf_link_update"))
		goto out;

	opts.old_prog_fd = bpf_program__fd(prog_clone);
	opts.flags = BPF_F_REPLACE;
	err = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "bpf_link_update"))
		goto out;
out:
	bpf_link__detach(link);
	test_skmsg_load_helpers__destroy(skel);
}

static void test_sockmap_update(enum bpf_map_type map_type)
{
	int err, prog, src;
	struct test_sockmap_update *skel;
	struct bpf_map *dst_map;
	const __u32 zero = 0;
	char dummy[14] = {0};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = dummy,
		.data_size_in = sizeof(dummy),
		.repeat = 1,
	);
	__s64 sk;

	sk = connected_socket_v4();
	if (!ASSERT_NEQ(sk, -1, "connected_socket_v4"))
		return;

	skel = test_sockmap_update__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto close_sk;

	prog = bpf_program__fd(skel->progs.copy_sock_map);
	src = bpf_map__fd(skel->maps.src);
	if (map_type == BPF_MAP_TYPE_SOCKMAP)
		dst_map = skel->maps.dst_sock_map;
	else
		dst_map = skel->maps.dst_sock_hash;

	err = bpf_map_update_elem(src, &zero, &sk, BPF_NOEXIST);
	if (!ASSERT_OK(err, "update_elem(src)"))
		goto out;

	err = bpf_prog_test_run_opts(prog, &topts);
	if (!ASSERT_OK(err, "test_run"))
		goto out;
	if (!ASSERT_NEQ(topts.retval, 0, "test_run retval"))
		goto out;

	compare_cookies(skel->maps.src, dst_map);

out:
	test_sockmap_update__destroy(skel);
close_sk:
	close(sk);
}

static void test_sockmap_invalid_update(void)
{
	struct test_sockmap_invalid_update *skel;

	skel = test_sockmap_invalid_update__open_and_load();
	if (!ASSERT_NULL(skel, "open_and_load"))
		test_sockmap_invalid_update__destroy(skel);
}

static void test_sockmap_copy(enum bpf_map_type map_type)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	int err, len, src_fd, iter_fd;
	union bpf_iter_link_info linfo = {};
	__u32 i, num_sockets, num_elems;
	struct bpf_iter_sockmap *skel;
	__s64 *sock_fd = NULL;
	struct bpf_link *link;
	struct bpf_map *src;
	char buf[64];

	skel = bpf_iter_sockmap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_sockmap__open_and_load"))
		return;

	if (map_type == BPF_MAP_TYPE_SOCKMAP) {
		src = skel->maps.sockmap;
		num_elems = bpf_map__max_entries(src);
		num_sockets = num_elems - 1;
	} else {
		src = skel->maps.sockhash;
		num_elems = bpf_map__max_entries(src) - 1;
		num_sockets = num_elems;
	}

	sock_fd = calloc(num_sockets, sizeof(*sock_fd));
	if (!ASSERT_OK_PTR(sock_fd, "calloc(sock_fd)"))
		goto out;

	for (i = 0; i < num_sockets; i++)
		sock_fd[i] = -1;

	src_fd = bpf_map__fd(src);

	for (i = 0; i < num_sockets; i++) {
		sock_fd[i] = connected_socket_v4();
		if (!ASSERT_NEQ(sock_fd[i], -1, "connected_socket_v4"))
			goto out;

		err = bpf_map_update_elem(src_fd, &i, &sock_fd[i], BPF_NOEXIST);
		if (!ASSERT_OK(err, "map_update"))
			goto out;
	}

	linfo.map.map_fd = src_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.copy, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create_iter"))
		goto free_link;

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (!ASSERT_GE(len, 0, "read"))
		goto close_iter;

	/* test results */
	if (!ASSERT_EQ(skel->bss->elems, num_elems, "elems"))
		goto close_iter;

	if (!ASSERT_EQ(skel->bss->socks, num_sockets, "socks"))
		goto close_iter;

	compare_cookies(src, skel->maps.dst);

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	for (i = 0; sock_fd && i < num_sockets; i++)
		if (sock_fd[i] >= 0)
			close(sock_fd[i]);
	if (sock_fd)
		free(sock_fd);
	bpf_iter_sockmap__destroy(skel);
}

#define TEST_NS "sockmap_basic"

struct sock_hash_key {
	__u32 bucket_key;
	__u64 cookie;
} __packed;

static void close_fds(int fds[], int fds_len)
{
	int i;

	for (i = 0; i < fds_len; i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

static __u64 socket_cookie(int fd)
{
	__u64 cookie;
	socklen_t cookie_len = sizeof(cookie);

	if (!ASSERT_OK(getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie,
				  &cookie_len), "getsockopt(SO_COOKIE)"))
		return 0;
	return cookie;
}

static bool has_socket(struct bpf_map *map, __u64 sk_cookie, int key_size)
{
	void *prev_key = NULL, *key = NULL;
	int map_fd = bpf_map__fd(map);
	bool found = false;
	__u64 cookie;
	int err;

	key = malloc(key_size);
	if (!ASSERT_OK_PTR(key, "malloc(key_size)"))
		goto cleanup;

	prev_key = malloc(key_size);
	if (!ASSERT_OK_PTR(key, "malloc(key_size)"))
		goto cleanup;

	err = bpf_map__get_next_key(map, NULL, key, key_size);
	if (!ASSERT_OK(err, "get_next_key"))
		goto cleanup;

	do {
		err = bpf_map_lookup_elem(map_fd, key, &cookie);
		if (!err)
			found = sk_cookie == cookie;
		else if (!ASSERT_EQ(err, -ENOENT, "bpf_map_lookup_elem"))
			goto cleanup;

		memcpy(prev_key, key, key_size);
	} while (!found &&
		 bpf_map__get_next_key(map, prev_key, key, key_size) == 0);
cleanup:
	if (prev_key)
		free(prev_key);
	if (key)
		free(key);
	return found;
}

static void test_sockmap_insert_sockops_and_destroy(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct test_sockmap_update *update_skel = NULL;
	static const int port0 = 10000, port1 = 10001;
	int prog_fd = -1, cg_fd = -1, iter_fd = -1;
	struct bpf_iter_sockmap *iter_skel = NULL;
	__u32 key_prefix = htonl((__u32)port0);
	int accept_serv[4] = {-1, -1, -1, -1};
	int tcp_clien[4] = {-1, -1, -1, -1};
	int udp_clien[4] = {-1, -1, -1, -1};
	union bpf_iter_link_info linfo = {};
	int tcp_serv[4] = {-1, -1, -1, -1};
	int udp_serv[4] = {-1, -1, -1, -1};
	struct nstoken *nstoken = NULL;
	int tcp_clien_cookies[4] = {};
	int udp_clien_cookies[4] = {};
	struct bpf_link *link = NULL;
	char buf[64];
	int len;
	int i;

	SYS_NOFAIL("ip netns del " TEST_NS);
	SYS(cleanup, "ip netns add %s", TEST_NS);
	SYS(cleanup, "ip -net %s link set dev lo up", TEST_NS);

	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto cleanup;

	cg_fd = test__join_cgroup("/sockmap_basic");
	if (!ASSERT_OK_FD(cg_fd, "join_cgroup"))
		goto cleanup;

	update_skel = test_sockmap_update__open_and_load();
	if (!ASSERT_OK_PTR(update_skel, "test_sockmap_update__open_and_load"))
		goto cleanup;

	iter_skel = bpf_iter_sockmap__open_and_load();
	if (!ASSERT_OK_PTR(iter_skel, "bpf_iter_sockmap__open_and_load"))
		goto cleanup;

	if (!ASSERT_OK(bpf_prog_attach(bpf_program__fd(update_skel->progs.insert_sock),
				       cg_fd, BPF_CGROUP_SOCK_OPS,
				       BPF_F_ALLOW_OVERRIDE),
		       "bpf_prog_attach"))
		goto cleanup;

	/* Create two servers on each port, port0 and port1, and connect a
	 * client to each.
	 */
	tcp_serv[0] = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", port0, 0);
	if (!ASSERT_OK_FD(tcp_serv[0], "start_server"))
		goto cleanup;

	tcp_serv[1] = start_server(AF_INET6, SOCK_STREAM, "::1", port0, 0);
	if (!ASSERT_OK_FD(tcp_serv[1], "start_server"))
		goto cleanup;

	tcp_serv[2] = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", port1, 0);
	if (!ASSERT_OK_FD(tcp_serv[2], "start_server"))
		goto cleanup;

	tcp_serv[3] = start_server(AF_INET6, SOCK_STREAM, "::1", port1, 0);
	if (!ASSERT_OK_FD(tcp_serv[3], "start_server"))
		goto cleanup;

	udp_serv[0] = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", port0, 0);
	if (!ASSERT_OK_FD(udp_serv[0], "start_server"))
		goto cleanup;

	udp_serv[1] = start_server(AF_INET6, SOCK_DGRAM, "::1", port0, 0);
	if (!ASSERT_OK_FD(udp_serv[1], "start_server"))
		goto cleanup;

	udp_serv[2] = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", port1, 0);
	if (!ASSERT_OK_FD(udp_serv[2], "start_server"))
		goto cleanup;

	udp_serv[3] = start_server(AF_INET6, SOCK_DGRAM, "::1", port1, 0);
	if (!ASSERT_OK_FD(udp_serv[3], "start_server"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(tcp_serv); i++) {
		tcp_clien[i] = connect_to_fd(tcp_serv[i], 0);
		if (!ASSERT_OK_FD(tcp_clien[i], "connect_to_fd"))
			goto cleanup;

		accept_serv[i] = accept(tcp_serv[i], NULL, NULL);
		if (!ASSERT_OK_FD(accept_serv[i], "accept"))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(udp_serv); i++) {
		udp_clien[i] = connect_to_fd(udp_serv[i], 0);
		if (!ASSERT_OK_FD(udp_clien[i], "connect_to_fd"))
			goto cleanup;
	}

	/* Ensure that sockets are connected. */
	for (i = 0; i < ARRAY_SIZE(tcp_clien); i++)
		if (!ASSERT_EQ(send(tcp_clien[i], "a", 1, 0), 1, "send"))
			goto cleanup;

	for (i = 0; i < ARRAY_SIZE(udp_clien); i++)
		if (!ASSERT_EQ(send(udp_clien[i], "a", 1, 0), 1, "send"))
			goto cleanup;

	/* Ensure that client sockets exist in the map and the hash. */
	if (!ASSERT_EQ(update_skel->bss->count,
		       ARRAY_SIZE(tcp_clien) + ARRAY_SIZE(udp_clien),
		       "count"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(tcp_clien); i++)
		tcp_clien_cookies[i] = socket_cookie(tcp_clien[i]);

	for (i = 0; i < ARRAY_SIZE(udp_clien); i++)
		udp_clien_cookies[i] = socket_cookie(udp_clien[i]);

	for (i = 0; i < ARRAY_SIZE(tcp_clien); i++) {
		if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_map,
					    tcp_clien_cookies[i],
					    sizeof(__u32)),
				 "has_socket"))
			goto cleanup;

		if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_hash,
					    tcp_clien_cookies[i],
					    sizeof(struct sock_hash_key)),
				 "has_socket"))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(udp_clien); i++) {
		if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_map,
					    udp_clien_cookies[i],
					    sizeof(__u32)),
				 "has_socket"))
			goto cleanup;

		if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_hash,
					    udp_clien_cookies[i],
					    sizeof(struct sock_hash_key)),
				 "has_socket"))
			goto cleanup;
	}

	/* Destroy sockets connected to port0. */
	linfo.map.map_fd = bpf_map__fd(update_skel->maps.sock_hash);
	linfo.map.sock_hash.key_prefix = (__u64)(void *)&key_prefix;
	linfo.map.sock_hash.key_prefix_len = sizeof(key_prefix);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(iter_skel->progs.destroy, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto cleanup;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_OK_FD(iter_fd, "bpf_iter_create"))
		goto cleanup;

	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (!ASSERT_GE(len, 0, "read"))
		goto cleanup;

	/* Ensure that sockets connected to port0 were destroyed. */
	if (!ASSERT_LT(send(tcp_clien[0], "a", 1, 0), 0, "send"))
		goto cleanup;
	if (!ASSERT_EQ(errno, ECONNABORTED, "ECONNABORTED"))
		goto cleanup;

	if (!ASSERT_LT(send(tcp_clien[1], "a", 1, 0), 0, "send"))
		goto cleanup;
	if (!ASSERT_EQ(errno, ECONNABORTED, "ECONNABORTED"))
		goto cleanup;

	if (!ASSERT_EQ(send(tcp_clien[2], "a", 1, 0), 1, "send"))
		goto cleanup;

	if (!ASSERT_EQ(send(tcp_clien[3], "a", 1, 0), 1, "send"))
		goto cleanup;

	if (!ASSERT_LT(send(udp_clien[0], "a", 1, 0), 0, "send"))
		goto cleanup;

	if (!ASSERT_LT(send(udp_clien[1], "a", 1, 0), 0, "send"))
		goto cleanup;

	if (!ASSERT_EQ(send(udp_clien[2], "a", 1, 0), 1, "send"))
		goto cleanup;

	if (!ASSERT_EQ(send(udp_clien[3], "a", 1, 0), 1, "send"))
		goto cleanup;

	/* Close and ensure that sockets are removed from maps. */
	close(tcp_clien[0]);
	close(tcp_clien[1]);
	close(udp_clien[0]);
	close(udp_clien[1]);

	/* Ensure that the sockets connected to port0 were removed from the
	 * maps.
	 */
	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_map,
				     tcp_clien_cookies[0],
				     sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_map,
				     tcp_clien_cookies[1],
				     sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_map,
				    tcp_clien_cookies[2],
				    sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_map,
				    tcp_clien_cookies[3],
				    sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_hash,
				     tcp_clien_cookies[0],
				     sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_hash,
				     tcp_clien_cookies[1],
				     sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_hash,
				    tcp_clien_cookies[2],
				    sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_hash,
				    tcp_clien_cookies[3],
				    sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_map,
				     udp_clien_cookies[0],
				     sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_map,
				     udp_clien_cookies[1],
				     sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_map,
				    udp_clien_cookies[2],
				    sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_map,
				    udp_clien_cookies[3],
				    sizeof(__u32)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_hash,
				     udp_clien_cookies[0],
				     sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_FALSE(has_socket(update_skel->maps.sock_hash,
				     udp_clien_cookies[1],
				     sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_hash,
				    udp_clien_cookies[2],
				    sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;

	if (!ASSERT_TRUE(has_socket(update_skel->maps.sock_hash,
				    udp_clien_cookies[3],
				    sizeof(struct sock_hash_key)),
			 "has_socket"))
		goto cleanup;
cleanup:
	close_fds(accept_serv, ARRAY_SIZE(accept_serv));
	close_fds(tcp_clien, ARRAY_SIZE(tcp_clien));
	close_fds(udp_clien, ARRAY_SIZE(udp_clien));
	close_fds(tcp_serv, ARRAY_SIZE(tcp_serv));
	close_fds(udp_serv, ARRAY_SIZE(udp_serv));
	if (prog_fd >= 0)
		bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
	if (cg_fd >= 0)
		close(cg_fd);
	if (iter_fd >= 0)
		close(iter_fd);
	bpf_link__destroy(link);
	test_sockmap_update__destroy(update_skel);
	bpf_iter_sockmap__destroy(iter_skel);
	close_netns(nstoken);
	SYS_NOFAIL("ip netns del " TEST_NS);
}

static void test_sockmap_skb_verdict_attach(enum bpf_attach_type first,
					    enum bpf_attach_type second)
{
	struct test_sockmap_skb_verdict_attach *skel;
	int err, map, verdict;

	skel = test_sockmap_skb_verdict_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	verdict = bpf_program__fd(skel->progs.prog_skb_verdict);
	map = bpf_map__fd(skel->maps.sock_map);

	err = bpf_prog_attach(verdict, map, first, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	err = bpf_prog_attach(verdict, map, second, 0);
	ASSERT_EQ(err, -EBUSY, "prog_attach_fail");

	err = bpf_prog_detach2(verdict, map, first);
	if (!ASSERT_OK(err, "bpf_prog_detach2"))
		goto out;
out:
	test_sockmap_skb_verdict_attach__destroy(skel);
}

static void test_sockmap_skb_verdict_attach_with_link(void)
{
	struct test_sockmap_skb_verdict_attach *skel;
	struct bpf_program *prog;
	struct bpf_link *link;
	int err, map;

	skel = test_sockmap_skb_verdict_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	prog = skel->progs.prog_skb_verdict;
	map = bpf_map__fd(skel->maps.sock_map);
	link = bpf_program__attach_sockmap(prog, map);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_sockmap"))
		goto out;

	bpf_link__detach(link);

	err = bpf_prog_attach(bpf_program__fd(prog), map, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	/* Fail since attaching with the same prog/map has been done. */
	link = bpf_program__attach_sockmap(prog, map);
	if (!ASSERT_ERR_PTR(link, "bpf_program__attach_sockmap"))
		bpf_link__detach(link);

	err = bpf_prog_detach2(bpf_program__fd(prog), map, BPF_SK_SKB_STREAM_VERDICT);
	if (!ASSERT_OK(err, "bpf_prog_detach2"))
		goto out;
out:
	test_sockmap_skb_verdict_attach__destroy(skel);
}

static __u32 query_prog_id(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_prog_get_info_by_fd") ||
	    !ASSERT_EQ(info_len, sizeof(info), "bpf_prog_get_info_by_fd"))
		return 0;

	return info.id;
}

static void test_sockmap_progs_query(enum bpf_attach_type attach_type)
{
	struct test_sockmap_progs_query *skel;
	int err, map_fd, verdict_fd;
	__u32 attach_flags = 0;
	__u32 prog_ids[3] = {};
	__u32 prog_cnt = 3;

	skel = test_sockmap_progs_query__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_sockmap_progs_query__open_and_load"))
		return;

	map_fd = bpf_map__fd(skel->maps.sock_map);

	if (attach_type == BPF_SK_MSG_VERDICT)
		verdict_fd = bpf_program__fd(skel->progs.prog_skmsg_verdict);
	else
		verdict_fd = bpf_program__fd(skel->progs.prog_skb_verdict);

	err = bpf_prog_query(map_fd, attach_type, 0 /* query flags */,
			     &attach_flags, prog_ids, &prog_cnt);
	ASSERT_OK(err, "bpf_prog_query failed");
	ASSERT_EQ(attach_flags,  0, "wrong attach_flags on query");
	ASSERT_EQ(prog_cnt, 0, "wrong program count on query");

	err = bpf_prog_attach(verdict_fd, map_fd, attach_type, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach failed"))
		goto out;

	prog_cnt = 1;
	err = bpf_prog_query(map_fd, attach_type, 0 /* query flags */,
			     &attach_flags, prog_ids, &prog_cnt);
	ASSERT_OK(err, "bpf_prog_query failed");
	ASSERT_EQ(attach_flags, 0, "wrong attach_flags on query");
	ASSERT_EQ(prog_cnt, 1, "wrong program count on query");
	ASSERT_EQ(prog_ids[0], query_prog_id(verdict_fd),
		  "wrong prog_ids on query");

	bpf_prog_detach2(verdict_fd, map_fd, attach_type);
out:
	test_sockmap_progs_query__destroy(skel);
}

#define MAX_EVENTS 10
static void test_sockmap_skb_verdict_shutdown(void)
{
	int n, err, map, verdict, c1 = -1, p1 = -1;
	struct epoll_event ev, events[MAX_EVENTS];
	struct test_sockmap_pass_prog *skel;
	int zero = 0;
	int epollfd;
	char b;

	skel = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	verdict = bpf_program__fd(skel->progs.prog_skb_verdict);
	map = bpf_map__fd(skel->maps.sock_map_rx);

	err = bpf_prog_attach(verdict, map, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	err = create_pair(AF_INET, SOCK_STREAM, &c1, &p1);
	if (err < 0)
		goto out;

	err = bpf_map_update_elem(map, &zero, &c1, BPF_NOEXIST);
	if (err < 0)
		goto out_close;

	shutdown(p1, SHUT_WR);

	ev.events = EPOLLIN;
	ev.data.fd = c1;

	epollfd = epoll_create1(0);
	if (!ASSERT_GT(epollfd, -1, "epoll_create(0)"))
		goto out_close;
	err = epoll_ctl(epollfd, EPOLL_CTL_ADD, c1, &ev);
	if (!ASSERT_OK(err, "epoll_ctl(EPOLL_CTL_ADD)"))
		goto out_close;
	err = epoll_wait(epollfd, events, MAX_EVENTS, -1);
	if (!ASSERT_EQ(err, 1, "epoll_wait(fd)"))
		goto out_close;

	n = recv(c1, &b, 1, MSG_DONTWAIT);
	ASSERT_EQ(n, 0, "recv(fin)");
out_close:
	close(c1);
	close(p1);
out:
	test_sockmap_pass_prog__destroy(skel);
}


static void test_sockmap_skb_verdict_fionread(bool pass_prog)
{
	int err, map, verdict, c0 = -1, c1 = -1, p0 = -1, p1 = -1;
	int expected, zero = 0, sent, recvd, avail;
	struct test_sockmap_pass_prog *pass = NULL;
	struct test_sockmap_drop_prog *drop = NULL;
	char buf[256] = "0123456789";

	if (pass_prog) {
		pass = test_sockmap_pass_prog__open_and_load();
		if (!ASSERT_OK_PTR(pass, "open_and_load"))
			return;
		verdict = bpf_program__fd(pass->progs.prog_skb_verdict);
		map = bpf_map__fd(pass->maps.sock_map_rx);
		expected = sizeof(buf);
	} else {
		drop = test_sockmap_drop_prog__open_and_load();
		if (!ASSERT_OK_PTR(drop, "open_and_load"))
			return;
		verdict = bpf_program__fd(drop->progs.prog_skb_verdict);
		map = bpf_map__fd(drop->maps.sock_map_rx);
		/* On drop data is consumed immediately and copied_seq inc'd */
		expected = 0;
	}


	err = bpf_prog_attach(verdict, map, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	err = create_socket_pairs(AF_INET, SOCK_STREAM, &c0, &c1, &p0, &p1);
	if (!ASSERT_OK(err, "create_socket_pairs()"))
		goto out;

	err = bpf_map_update_elem(map, &zero, &c1, BPF_NOEXIST);
	if (!ASSERT_OK(err, "bpf_map_update_elem(c1)"))
		goto out_close;

	sent = xsend(p1, &buf, sizeof(buf), 0);
	ASSERT_EQ(sent, sizeof(buf), "xsend(p0)");
	err = ioctl(c1, FIONREAD, &avail);
	ASSERT_OK(err, "ioctl(FIONREAD) error");
	ASSERT_EQ(avail, expected, "ioctl(FIONREAD)");
	/* On DROP test there will be no data to read */
	if (pass_prog) {
		recvd = recv_timeout(c1, &buf, sizeof(buf), MSG_DONTWAIT, IO_TIMEOUT_SEC);
		ASSERT_EQ(recvd, sizeof(buf), "recv_timeout(c0)");
	}

out_close:
	close(c0);
	close(p0);
	close(c1);
	close(p1);
out:
	if (pass_prog)
		test_sockmap_pass_prog__destroy(pass);
	else
		test_sockmap_drop_prog__destroy(drop);
}

static void test_sockmap_skb_verdict_change_tail(void)
{
	struct test_sockmap_change_tail *skel;
	int err, map, verdict;
	int c1, p1, sent, recvd;
	int zero = 0;
	char buf[2];

	skel = test_sockmap_change_tail__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	verdict = bpf_program__fd(skel->progs.prog_skb_verdict);
	map = bpf_map__fd(skel->maps.sock_map_rx);

	err = bpf_prog_attach(verdict, map, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;
	err = create_pair(AF_INET, SOCK_STREAM, &c1, &p1);
	if (!ASSERT_OK(err, "create_pair()"))
		goto out;
	err = bpf_map_update_elem(map, &zero, &c1, BPF_NOEXIST);
	if (!ASSERT_OK(err, "bpf_map_update_elem(c1)"))
		goto out_close;
	sent = xsend(p1, "Tr", 2, 0);
	ASSERT_EQ(sent, 2, "xsend(p1)");
	recvd = recv(c1, buf, 2, 0);
	ASSERT_EQ(recvd, 1, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, 0, "change_tail_ret");

	sent = xsend(p1, "G", 1, 0);
	ASSERT_EQ(sent, 1, "xsend(p1)");
	recvd = recv(c1, buf, 2, 0);
	ASSERT_EQ(recvd, 2, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, 0, "change_tail_ret");

	sent = xsend(p1, "E", 1, 0);
	ASSERT_EQ(sent, 1, "xsend(p1)");
	recvd = recv(c1, buf, 1, 0);
	ASSERT_EQ(recvd, 1, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, -EINVAL, "change_tail_ret");

out_close:
	close(c1);
	close(p1);
out:
	test_sockmap_change_tail__destroy(skel);
}

static void test_sockmap_skb_verdict_peek_helper(int map)
{
	int err, c1, p1, zero = 0, sent, recvd, avail;
	char snd[256] = "0123456789";
	char rcv[256] = "0";

	err = create_pair(AF_INET, SOCK_STREAM, &c1, &p1);
	if (!ASSERT_OK(err, "create_pair()"))
		return;

	err = bpf_map_update_elem(map, &zero, &c1, BPF_NOEXIST);
	if (!ASSERT_OK(err, "bpf_map_update_elem(c1)"))
		goto out_close;

	sent = xsend(p1, snd, sizeof(snd), 0);
	ASSERT_EQ(sent, sizeof(snd), "xsend(p1)");
	recvd = recv(c1, rcv, sizeof(rcv), MSG_PEEK);
	ASSERT_EQ(recvd, sizeof(rcv), "recv(c1)");
	err = ioctl(c1, FIONREAD, &avail);
	ASSERT_OK(err, "ioctl(FIONREAD) error");
	ASSERT_EQ(avail, sizeof(snd), "after peek ioctl(FIONREAD)");
	recvd = recv(c1, rcv, sizeof(rcv), 0);
	ASSERT_EQ(recvd, sizeof(rcv), "recv(p0)");
	err = ioctl(c1, FIONREAD, &avail);
	ASSERT_OK(err, "ioctl(FIONREAD) error");
	ASSERT_EQ(avail, 0, "after read ioctl(FIONREAD)");

out_close:
	close(c1);
	close(p1);
}

static void test_sockmap_skb_verdict_peek(void)
{
	struct test_sockmap_pass_prog *pass;
	int err, map, verdict;

	pass = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(pass, "open_and_load"))
		return;
	verdict = bpf_program__fd(pass->progs.prog_skb_verdict);
	map = bpf_map__fd(pass->maps.sock_map_rx);

	err = bpf_prog_attach(verdict, map, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	test_sockmap_skb_verdict_peek_helper(map);

out:
	test_sockmap_pass_prog__destroy(pass);
}

static void test_sockmap_skb_verdict_peek_with_link(void)
{
	struct test_sockmap_pass_prog *pass;
	struct bpf_program *prog;
	struct bpf_link *link;
	int err, map;

	pass = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(pass, "open_and_load"))
		return;
	prog = pass->progs.prog_skb_verdict;
	map = bpf_map__fd(pass->maps.sock_map_rx);
	link = bpf_program__attach_sockmap(prog, map);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_sockmap"))
		goto out;

	err = bpf_link__update_program(link, pass->progs.prog_skb_verdict_clone);
	if (!ASSERT_OK(err, "bpf_link__update_program"))
		goto out;

	/* Fail since a prog with different attach type attempts to do update. */
	err = bpf_link__update_program(link, pass->progs.prog_skb_parser);
	if (!ASSERT_ERR(err, "bpf_link__update_program"))
		goto out;

	test_sockmap_skb_verdict_peek_helper(map);
	ASSERT_EQ(pass->bss->clone_called, 1, "clone_called");
out:
	bpf_link__detach(link);
	test_sockmap_pass_prog__destroy(pass);
}

static void test_sockmap_unconnected_unix(void)
{
	int err, map, stream = 0, dgram = 0, zero = 0;
	struct test_sockmap_pass_prog *skel;

	skel = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map = bpf_map__fd(skel->maps.sock_map_rx);

	stream = xsocket(AF_UNIX, SOCK_STREAM, 0);
	if (stream < 0)
		return;

	dgram = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	if (dgram < 0) {
		close(stream);
		return;
	}

	err = bpf_map_update_elem(map, &zero, &stream, BPF_ANY);
	ASSERT_ERR(err, "bpf_map_update_elem(stream)");

	err = bpf_map_update_elem(map, &zero, &dgram, BPF_ANY);
	ASSERT_OK(err, "bpf_map_update_elem(dgram)");

	close(stream);
	close(dgram);
}

static void test_sockmap_many_socket(void)
{
	struct test_sockmap_pass_prog *skel;
	int stream[2], dgram, udp, tcp;
	int i, err, map, entry = 0;

	skel = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map = bpf_map__fd(skel->maps.sock_map_rx);

	dgram = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	if (dgram < 0) {
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	tcp = connected_socket_v4();
	if (!ASSERT_GE(tcp, 0, "connected_socket_v4")) {
		close(dgram);
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	udp = xsocket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (udp < 0) {
		close(dgram);
		close(tcp);
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
	ASSERT_OK(err, "socketpair(af_unix, sock_stream)");
	if (err)
		goto out;

	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map, &entry, &stream[0], BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(stream)");
	}
	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map, &entry, &dgram, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(dgram)");
	}
	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map, &entry, &udp, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(udp)");
	}
	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map, &entry, &tcp, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(tcp)");
	}
	for (entry--; entry >= 0; entry--) {
		err = bpf_map_delete_elem(map, &entry);
		ASSERT_OK(err, "bpf_map_delete_elem(entry)");
	}

	close(stream[0]);
	close(stream[1]);
out:
	close(dgram);
	close(tcp);
	close(udp);
	test_sockmap_pass_prog__destroy(skel);
}

static void test_sockmap_many_maps(void)
{
	struct test_sockmap_pass_prog *skel;
	int stream[2], dgram, udp, tcp;
	int i, err, map[2], entry = 0;

	skel = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map[0] = bpf_map__fd(skel->maps.sock_map_rx);
	map[1] = bpf_map__fd(skel->maps.sock_map_tx);

	dgram = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	if (dgram < 0) {
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	tcp = connected_socket_v4();
	if (!ASSERT_GE(tcp, 0, "connected_socket_v4")) {
		close(dgram);
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	udp = xsocket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (udp < 0) {
		close(dgram);
		close(tcp);
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
	ASSERT_OK(err, "socketpair(af_unix, sock_stream)");
	if (err)
		goto out;

	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map[i], &entry, &stream[0], BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(stream)");
	}
	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map[i], &entry, &dgram, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(dgram)");
	}
	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map[i], &entry, &udp, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(udp)");
	}
	for (i = 0; i < 2; i++, entry++) {
		err = bpf_map_update_elem(map[i], &entry, &tcp, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(tcp)");
	}
	for (entry--; entry >= 0; entry--) {
		err = bpf_map_delete_elem(map[1], &entry);
		entry--;
		ASSERT_OK(err, "bpf_map_delete_elem(entry)");
		err = bpf_map_delete_elem(map[0], &entry);
		ASSERT_OK(err, "bpf_map_delete_elem(entry)");
	}

	close(stream[0]);
	close(stream[1]);
out:
	close(dgram);
	close(tcp);
	close(udp);
	test_sockmap_pass_prog__destroy(skel);
}

static void test_sockmap_same_sock(void)
{
	struct test_sockmap_pass_prog *skel;
	int stream[2], dgram, udp, tcp;
	int i, err, map, zero = 0;

	skel = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map = bpf_map__fd(skel->maps.sock_map_rx);

	dgram = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	if (dgram < 0) {
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	tcp = connected_socket_v4();
	if (!ASSERT_GE(tcp, 0, "connected_socket_v4")) {
		close(dgram);
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	udp = xsocket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (udp < 0) {
		close(dgram);
		close(tcp);
		test_sockmap_pass_prog__destroy(skel);
		return;
	}

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
	ASSERT_OK(err, "socketpair(af_unix, sock_stream)");
	if (err) {
		close(tcp);
		goto out;
	}

	for (i = 0; i < 2; i++) {
		err = bpf_map_update_elem(map, &zero, &stream[0], BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(stream)");
	}
	for (i = 0; i < 2; i++) {
		err = bpf_map_update_elem(map, &zero, &dgram, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(dgram)");
	}
	for (i = 0; i < 2; i++) {
		err = bpf_map_update_elem(map, &zero, &udp, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(udp)");
	}
	for (i = 0; i < 2; i++) {
		err = bpf_map_update_elem(map, &zero, &tcp, BPF_ANY);
		ASSERT_OK(err, "bpf_map_update_elem(tcp)");
	}

	close(tcp);
	err = bpf_map_delete_elem(map, &zero);
	ASSERT_ERR(err, "bpf_map_delete_elem(entry)");

	close(stream[0]);
	close(stream[1]);
out:
	close(dgram);
	close(udp);
	test_sockmap_pass_prog__destroy(skel);
}

static void test_sockmap_skb_verdict_vsock_poll(void)
{
	struct test_sockmap_pass_prog *skel;
	int err, map, conn, peer;
	struct bpf_program *prog;
	struct bpf_link *link;
	char buf = 'x';
	int zero = 0;

	skel = test_sockmap_pass_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (create_pair(AF_VSOCK, SOCK_STREAM, &conn, &peer))
		goto destroy;

	prog = skel->progs.prog_skb_verdict;
	map = bpf_map__fd(skel->maps.sock_map_rx);
	link = bpf_program__attach_sockmap(prog, map);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_sockmap"))
		goto close;

	err = bpf_map_update_elem(map, &zero, &conn, BPF_ANY);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto detach;

	if (xsend(peer, &buf, 1, 0) != 1)
		goto detach;

	err = poll_read(conn, IO_TIMEOUT_SEC);
	if (!ASSERT_OK(err, "poll"))
		goto detach;

	if (xrecv_nonblock(conn, &buf, 1, 0) != 1)
		FAIL("xrecv_nonblock");
detach:
	bpf_link__detach(link);
close:
	xclose(conn);
	xclose(peer);
destroy:
	test_sockmap_pass_prog__destroy(skel);
}

static void test_sockmap_vsock_unconnected(void)
{
	struct sockaddr_storage addr;
	int map, s, zero = 0;
	socklen_t alen;

	map = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, NULL, sizeof(int),
			     sizeof(int), 1, NULL);
	if (!ASSERT_OK_FD(map, "bpf_map_create"))
		return;

	s = xsocket(AF_VSOCK, SOCK_STREAM, 0);
	if (s < 0)
		goto close_map;

	/* Fail connect(), but trigger transport assignment. */
	init_addr_loopback(AF_VSOCK, &addr, &alen);
	if (!ASSERT_ERR(connect(s, sockaddr(&addr), alen), "connect"))
		goto close_sock;

	ASSERT_ERR(bpf_map_update_elem(map, &zero, &s, BPF_ANY), "map_update");

close_sock:
	xclose(s);
close_map:
	xclose(map);
}

void test_sockmap_basic(void)
{
	if (test__start_subtest("sockmap create_update_free"))
		test_sockmap_create_update_free(BPF_MAP_TYPE_SOCKMAP);
	if (test__start_subtest("sockhash create_update_free"))
		test_sockmap_create_update_free(BPF_MAP_TYPE_SOCKHASH);
	if (test__start_subtest("sockmap vsock delete on close"))
		test_sockmap_vsock_delete_on_close();
	if (test__start_subtest("sockmap sk_msg load helpers"))
		test_skmsg_helpers(BPF_MAP_TYPE_SOCKMAP);
	if (test__start_subtest("sockhash sk_msg load helpers"))
		test_skmsg_helpers(BPF_MAP_TYPE_SOCKHASH);
	if (test__start_subtest("sockmap update"))
		test_sockmap_update(BPF_MAP_TYPE_SOCKMAP);
	if (test__start_subtest("sockhash update"))
		test_sockmap_update(BPF_MAP_TYPE_SOCKHASH);
	if (test__start_subtest("sockmap update in unsafe context"))
		test_sockmap_invalid_update();
	if (test__start_subtest("sockmap copy"))
		test_sockmap_copy(BPF_MAP_TYPE_SOCKMAP);
	if (test__start_subtest("sockhash copy"))
		test_sockmap_copy(BPF_MAP_TYPE_SOCKHASH);
	if (test__start_subtest("sock(map|hash) sockops insert and destroy"))
		test_sockmap_insert_sockops_and_destroy();
	if (test__start_subtest("sockmap skb_verdict attach")) {
		test_sockmap_skb_verdict_attach(BPF_SK_SKB_VERDICT,
						BPF_SK_SKB_STREAM_VERDICT);
		test_sockmap_skb_verdict_attach(BPF_SK_SKB_STREAM_VERDICT,
						BPF_SK_SKB_VERDICT);
	}
	if (test__start_subtest("sockmap skb_verdict attach_with_link"))
		test_sockmap_skb_verdict_attach_with_link();
	if (test__start_subtest("sockmap msg_verdict progs query"))
		test_sockmap_progs_query(BPF_SK_MSG_VERDICT);
	if (test__start_subtest("sockmap stream_parser progs query"))
		test_sockmap_progs_query(BPF_SK_SKB_STREAM_PARSER);
	if (test__start_subtest("sockmap stream_verdict progs query"))
		test_sockmap_progs_query(BPF_SK_SKB_STREAM_VERDICT);
	if (test__start_subtest("sockmap skb_verdict progs query"))
		test_sockmap_progs_query(BPF_SK_SKB_VERDICT);
	if (test__start_subtest("sockmap skb_verdict shutdown"))
		test_sockmap_skb_verdict_shutdown();
	if (test__start_subtest("sockmap skb_verdict fionread"))
		test_sockmap_skb_verdict_fionread(true);
	if (test__start_subtest("sockmap skb_verdict fionread on drop"))
		test_sockmap_skb_verdict_fionread(false);
	if (test__start_subtest("sockmap skb_verdict change tail"))
		test_sockmap_skb_verdict_change_tail();
	if (test__start_subtest("sockmap skb_verdict msg_f_peek"))
		test_sockmap_skb_verdict_peek();
	if (test__start_subtest("sockmap skb_verdict msg_f_peek with link"))
		test_sockmap_skb_verdict_peek_with_link();
	if (test__start_subtest("sockmap unconnected af_unix"))
		test_sockmap_unconnected_unix();
	if (test__start_subtest("sockmap one socket to many map entries"))
		test_sockmap_many_socket();
	if (test__start_subtest("sockmap one socket to many maps"))
		test_sockmap_many_maps();
	if (test__start_subtest("sockmap same socket replace"))
		test_sockmap_same_sock();
	if (test__start_subtest("sockmap sk_msg attach sockmap helpers with link"))
		test_skmsg_helpers_with_link(BPF_MAP_TYPE_SOCKMAP);
	if (test__start_subtest("sockhash sk_msg attach sockhash helpers with link"))
		test_skmsg_helpers_with_link(BPF_MAP_TYPE_SOCKHASH);
	if (test__start_subtest("sockmap skb_verdict vsock poll"))
		test_sockmap_skb_verdict_vsock_poll();
	if (test__start_subtest("sockmap vsock unconnected"))
		test_sockmap_vsock_unconnected();
}
