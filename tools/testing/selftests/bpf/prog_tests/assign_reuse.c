// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */
#include <uapi/linux/if_link.h>
#include <test_progs.h>
#include <stdint.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "network_helpers.h"
#include "test_assign_reuse.skel.h"

#define NS_TEST "assign_reuse"
#define LOOPBACK 1
#define PORT 4443
#define CLIENT_PORT_MIN 32768
#define TEST_ITERATIONS 8
#define IO_TIMEOUT_MS 100
#define POLL_RETRIES 5000
#define POLL_INTERVAL_US 1000
#define NR_EXCHANGES \
	ARRAY_SIZE(((struct test_assign_reuse__bss *)0)->exchanges)

struct reuse_client {
	struct test_assign_reuse *skel;
	__u32 slot;
	int held_fd;
};

static bool setup_family(int family)
{
	int fd, ret;

	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0 && errno == EAFNOSUPPORT) {
		printf("SKIP: address family %d is unavailable\n", family);
		test__skip();
		return false;
	}
	if (!ASSERT_GE(fd, 0, "family_probe"))
		return false;
	close(fd);
	if (family != AF_INET6)
		return true;
	ret = write_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	return ASSERT_OK(ret, "enable_ipv6");
}

static int attach_reuseport(int sock_fd, int prog_fd)
{
	return setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
			  &prog_fd, sizeof(prog_fd));
}

static __u64 cookie(int fd)
{
	__u64 cookie = 0;
	socklen_t cookie_len = sizeof(cookie);
	int ret;

	ret = getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_len);
	ASSERT_OK(ret, "cookie");
	ASSERT_GT(cookie, 0, "cookie_invalid");

	return cookie;
}

static int echo_test_udp_opts(int fd_sv,
			      const struct network_helper_opts *opts)
{
	struct sockaddr_storage addr = {};
	socklen_t len = sizeof(addr);
	int fd_cl = -1, ret;
	char buff[1] = {};

	fd_cl = connect_to_fd_opts(fd_sv, opts);
	ASSERT_GT(fd_cl, 0, "create_client");
	ASSERT_EQ(getsockname(fd_cl, (void *)&addr, &len), 0, "getsockname");

	ASSERT_EQ(send(fd_cl, buff, sizeof(buff), 0), 1, "send_client");

	ret = recv(fd_sv, buff, sizeof(buff), 0);
	if (ret < 0) {
		close(fd_cl);
		return errno;
	}

	ASSERT_EQ(ret, 1, "recv_server");
	ASSERT_EQ(sendto(fd_sv, buff, sizeof(buff), 0, (void *)&addr, len), 1, "send_server");
	ASSERT_EQ(recv(fd_cl, buff, sizeof(buff), 0), 1, "recv_client");
	close(fd_cl);
	return 0;
}

static int echo_test_udp(int fd_sv)
{
	struct network_helper_opts opts = { .timeout_ms = IO_TIMEOUT_MS };

	return echo_test_udp_opts(fd_sv, &opts);
}

static int echo_test_tcp_opts(int fd_sv,
			      const struct network_helper_opts *opts)
{
	int fd_cl = -1, fd_sv_cl = -1;
	char buff[1] = {};

	fd_cl = connect_to_fd_opts(fd_sv, opts);
	if (fd_cl < 0)
		return errno;

	fd_sv_cl = accept(fd_sv, NULL, NULL);
	ASSERT_GE(fd_sv_cl, 0, "accept_fd");

	ASSERT_EQ(send(fd_cl, buff, sizeof(buff), 0), 1, "send_client");
	ASSERT_EQ(recv(fd_sv_cl, buff, sizeof(buff), 0), 1, "recv_server");
	ASSERT_EQ(send(fd_sv_cl, buff, sizeof(buff), 0), 1, "send_server");
	ASSERT_EQ(recv(fd_cl, buff, sizeof(buff), 0), 1, "recv_client");
	close(fd_sv_cl);
	close(fd_cl);
	return 0;
}

static int echo_test_tcp(int fd_sv)
{
	struct network_helper_opts opts = { .timeout_ms = IO_TIMEOUT_MS };

	return echo_test_tcp_opts(fd_sv, &opts);
}

static int prepare_reuse_client(int fd, void *arg)
{
	struct sockaddr_storage addr = {};
	struct reuse_client *client = arg;
	socklen_t len = sizeof(addr);
	int port, ret, i;

	if (getsockname(fd, (void *)&addr, &len))
		return -1;
	ret = make_sockaddr(addr.ss_family, addr.ss_family == AF_INET ?
			    "127.0.0.1" : "::1", 0, &addr, &len);
	if (ret)
		return -1;
	for (port = CLIENT_PORT_MIN; port <= UINT16_MAX; port++) {
		for (i = 0; i < client->slot; i++) {
			if (client->skel->bss->exchanges[i].source_port ==
			    htons(port))
				break;
		}
		if (i < client->slot)
			continue;
		if (addr.ss_family == AF_INET)
			((struct sockaddr_in *)&addr)->sin_port = htons(port);
		else
			((struct sockaddr_in6 *)&addr)->sin6_port = htons(port);
		ret = bind(fd, (void *)&addr, len);
		if (!ret)
			break;
		if (errno != EADDRINUSE)
			return -1;
	}
	if (port > UINT16_MAX)
		return -1;
	client->held_fd = dup(fd);
	if (client->held_fd < 0)
		return -1;
	__atomic_store_n(&client->skel->bss->exchanges[client->slot].source_port,
			 htons(port), __ATOMIC_RELEASE);
	return 0;
}

static bool run_reuse_exchange(struct test_assign_reuse *skel, int fd,
			       int sotype, __u32 index, bool drop,
			       struct reuse_client *client, __u32 slot,
			       __u64 expected_cookie)
{
	struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = prepare_reuse_client,
		.cb_opts = client,
	};
	int expected, ret;

	client->skel = skel;
	client->slot = slot;
	skel->bss->exchanges[slot].expected_cookie = expected_cookie;
	skel->bss->exchanges[slot].index = index;
	skel->bss->exchanges[slot].drop = drop;
	if (sotype == SOCK_STREAM) {
		expected = drop ? ECONNREFUSED : 0;
		ret = echo_test_tcp_opts(fd, &opts);
	} else {
		expected = drop ? EAGAIN : 0;
		ret = echo_test_udp_opts(fd, &opts);
	}
	return ASSERT_EQ(ret, expected, "exchange_result");
}

static void check_reuse_exchanges(struct test_assign_reuse *skel)
{
	typeof(skel->bss->exchanges[0]) *exchange;
	bool complete = false;
	int i, j;

	for (i = 0; i < POLL_RETRIES; i++) {
		complete = true;
		for (j = 0; j < ARRAY_SIZE(skel->bss->exchanges); j++) {
			exchange = &skel->bss->exchanges[j];
			if (!exchange->source_port)
				continue;
			if (__atomic_load_n(&exchange->reuse_calls,
					    __ATOMIC_ACQUIRE) !=
			    exchange->assign_calls - exchange->assign_errors)
				complete = false;
		}
		if (complete)
			break;
		usleep(POLL_INTERVAL_US);
	}
	ASSERT_TRUE(complete, "reuseport_drained");
	for (i = 0; i < ARRAY_SIZE(skel->bss->exchanges); i++) {
		exchange = &skel->bss->exchanges[i];
		if (!exchange->source_port)
			continue;
		ASSERT_GT(exchange->assign_calls, 0, "final_assign_calls");
		ASSERT_EQ(exchange->reuse_calls, exchange->assign_calls,
			  "final_reuse_calls");
		ASSERT_EQ(exchange->assign_errors, 0, "final_assign_errors");
		ASSERT_EQ(exchange->select_errors, 0, "final_select_errors");
		ASSERT_EQ(exchange->cookie_errors, 0, "final_cookie_errors");
		ASSERT_EQ(exchange->sk_cookie, exchange->expected_cookie,
			  "final_assigned_socket_cookie");
	}
}

static void run_assign_reuse(int family, int sotype, const char *ip, __u16 port,
			     bool egress)
{
	bool hook_created = false, tc_attached = false;
	int ret, fd_tc, fd_accept, fd_drop, fd_map;
	struct reuse_client clients[NR_EXCHANGES];
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.ifindex = LOOPBACK,
		.attach_point = BPF_TC_INGRESS,
	);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		.handle = 1,
		.priority = 1,
	);
	struct test_assign_reuse *skel = NULL;
	int nr_listens = egress ? 2 : 1;
	const int zero = 0;
	int *fd_sv = NULL;
	__u32 slot = 0;
	__u64 fd_val;
	int i, j;

	for (i = 0; i < ARRAY_SIZE(clients); i++)
		clients[i].held_fd = -1;
	if (!setup_family(family))
		goto cleanup;
	skel = test_assign_reuse__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->rodata->dest_port = port;
	skel->rodata->select_sock = egress;
	if (egress) {
		ret = kern_sync_rcu();
		if (ret && (errno == ENOSYS || errno == EINVAL)) {
			printf("SKIP: RCU synchronization is unavailable\n");
			test__skip();
			goto cleanup;
		}
		if (!ASSERT_OK(ret, "sync_rcu_probe"))
			goto cleanup;
		tc_hook.attach_point = BPF_TC_EGRESS;
		if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/conf/lo/accept_local", "1"),
			       "accept_local") ||
		    !ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/conf/lo/route_localnet", "1"),
			       "route_localnet"))
			goto cleanup;
	}

	ret = test_assign_reuse__load(skel);
	if (!ASSERT_OK(ret, "skel_load"))
		goto cleanup;

	ASSERT_EQ(skel->bss->sk_cookie_seen, 0, "cookie_init");

	fd_tc = bpf_program__fd(skel->progs.tc_main);
	fd_accept = bpf_program__fd(skel->progs.reuse_accept);
	fd_drop = bpf_program__fd(skel->progs.reuse_drop);
	fd_map = bpf_map__fd(skel->maps.sk_map);

	fd_sv = start_reuseport_server(family, sotype, ip, port, IO_TIMEOUT_MS,
				       nr_listens);
	if (!ASSERT_NEQ(fd_sv, NULL, "start_reuseport_server"))
		goto cleanup;

	ret = attach_reuseport(*fd_sv, fd_drop);
	if (!ASSERT_OK(ret, "attach_reuseport"))
		goto cleanup;

	fd_val = *fd_sv;
	ret = bpf_map_update_elem(fd_map, &zero, &fd_val, BPF_NOEXIST);
	if (!ASSERT_OK(ret, "bpf_sk_map"))
		goto cleanup;
	for (i = 1; i < nr_listens; i++) {
		fd_val = fd_sv[i];
		ret = bpf_map_update_elem(fd_map, &i, &fd_val, BPF_NOEXIST);
		if (!ASSERT_OK(ret, "sk_map_update"))
			goto cleanup;
	}

	ret = bpf_tc_hook_create(&tc_hook);
	if (ret == 0)
		hook_created = true;
	ret = ret == -EEXIST ? 0 : ret;
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto cleanup;

	tc_opts.prog_fd = fd_tc;
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto cleanup;
	tc_attached = true;

	if (egress) {
		if (!run_reuse_exchange(skel, fd_sv[0], sotype, 0, true,
					&clients[slot], slot, cookie(fd_sv[0])))
			goto cleanup;
		slot++;
		if (!ASSERT_OK(attach_reuseport(*fd_sv, fd_accept),
			       "attach_reuseport(accept)"))
			goto cleanup;
		if (!run_reuse_exchange(skel, fd_sv[0], sotype, 0, false,
					&clients[slot], slot, cookie(fd_sv[0])))
			goto cleanup;
		slot++;
		for (i = 0; i < nr_listens; i++) {
			for (j = 0; j < TEST_ITERATIONS; j++) {
				if (!run_reuse_exchange(skel, fd_sv[i], sotype,
							i, false, &clients[slot],
							slot, cookie(fd_sv[0])))
					goto cleanup;
				slot++;
			}
		}
		goto cleanup;
	}

	if (sotype == SOCK_STREAM)
		ASSERT_EQ(echo_test_tcp(*fd_sv), ECONNREFUSED, "drop_tcp");
	else
		ASSERT_EQ(echo_test_udp(*fd_sv), EAGAIN, "drop_udp");
	ASSERT_EQ(skel->bss->reuseport_executed, 1, "program executed once");
	ASSERT_EQ(skel->bss->assign_calls, 1, "drop_assign_calls");
	ASSERT_EQ(skel->bss->assign_errors, 0, "drop_assign_errors");

	skel->bss->sk_cookie_seen = 0;
	skel->bss->reuseport_executed = 0;
	ASSERT_OK(attach_reuseport(*fd_sv, fd_accept), "attach_reuseport(accept)");

	if (sotype == SOCK_STREAM)
		ASSERT_EQ(echo_test_tcp(*fd_sv), 0, "echo_tcp");
	else
		ASSERT_EQ(echo_test_udp(*fd_sv), 0, "echo_udp");

	ASSERT_EQ(skel->bss->sk_cookie_seen, cookie(*fd_sv),
		  "cookie_mismatch");
	ASSERT_EQ(skel->bss->reuseport_executed, 1, "program executed once");

cleanup:
	for (i = 0; i < ARRAY_SIZE(clients); i++) {
		if (clients[i].held_fd >= 0)
			close(clients[i].held_fd);
	}
	if (tc_attached) {
		tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
		ret = bpf_tc_detach(&tc_hook, &tc_opts);
		if (ASSERT_OK(ret, "bpf_tc_detach") && egress &&
		    ASSERT_OK(kern_sync_rcu(), "sync_assignments"))
			check_reuse_exchanges(skel);
	}
	if (hook_created) {
		tc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&tc_hook);
	}
	test_assign_reuse__destroy(skel);
	free_fds(fd_sv, nr_listens);
}

void test_assign_reuse(void)
{
	struct nstoken *tok = NULL;

	SYS(out, "ip netns add %s", NS_TEST);
	SYS(cleanup, "ip -net %s link set dev lo up", NS_TEST);

	tok = open_netns(NS_TEST);
	if (!ASSERT_NEQ(tok, NULL, "netns token"))
		goto cleanup;

	if (test__start_subtest("tcpv4"))
		run_assign_reuse(AF_INET, SOCK_STREAM, "127.0.0.1", PORT, false);
	if (test__start_subtest("tcpv6"))
		run_assign_reuse(AF_INET6, SOCK_STREAM, "::1", PORT, false);
	if (test__start_subtest("udpv4"))
		run_assign_reuse(AF_INET, SOCK_DGRAM, "127.0.0.1", PORT, false);
	if (test__start_subtest("udpv6"))
		run_assign_reuse(AF_INET6, SOCK_DGRAM, "::1", PORT, false);
	if (test__start_subtest("tcpv4_egress"))
		run_assign_reuse(AF_INET, SOCK_STREAM, "127.0.0.1", PORT, true);
	if (test__start_subtest("tcpv6_egress"))
		run_assign_reuse(AF_INET6, SOCK_STREAM, "::1", PORT, true);
	if (test__start_subtest("udpv4_egress"))
		run_assign_reuse(AF_INET, SOCK_DGRAM, "127.0.0.1", PORT, true);
	if (test__start_subtest("udpv6_egress"))
		run_assign_reuse(AF_INET6, SOCK_DGRAM, "::1", PORT, true);

cleanup:
	close_netns(tok);
	SYS_NOFAIL("ip netns delete %s", NS_TEST);
out:
	return;
}
