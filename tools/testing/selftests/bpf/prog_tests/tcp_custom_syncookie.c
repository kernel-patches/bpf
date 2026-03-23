// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>

#include "test_progs.h"
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "test_tcp_custom_syncookie.skel.h"

static struct test_tcp_custom_syncookie_case {
	int family, type;
	char addr[16];
	char name[10];
} test_cases[] = {
	{
		.name = "IPv4 TCP",
		.family = AF_INET,
		.type = SOCK_STREAM,
		.addr = "127.0.0.1",
	},
	{
		.name = "IPv6 TCP",
		.family = AF_INET6,
		.type = SOCK_STREAM,
		.addr = "::1",
	},
};

static int setup_netns(void)
{
	if (!ASSERT_OK(unshare(CLONE_NEWNET), "create netns"))
		return -1;

	if (!ASSERT_OK(system("ip link set dev lo up"), "ip"))
		goto err;

	if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/tcp_ecn", "1"),
		       "write_sysctl"))
		goto err;

	return 0;
err:
	return -1;
}

static int setup_tc(int prog_fd)
{
	LIBBPF_OPTS(bpf_tc_hook, qdisc_lo, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach, .prog_fd = prog_fd);

	qdisc_lo.ifindex = if_nametoindex("lo");
	if (!ASSERT_OK(bpf_tc_hook_create(&qdisc_lo), "qdisc add dev lo clsact"))
		goto err;

	if (!ASSERT_OK(bpf_tc_attach(&qdisc_lo, &tc_attach),
		       "filter add dev lo ingress"))
		goto err;

	return 0;
err:
	return -1;
}

#define msg "Hello World"
#define msglen 11

static void transfer_message(int sender, int receiver)
{
	char buf[msglen];
	int ret;

	ret = send(sender, msg, msglen, 0);
	if (!ASSERT_EQ(ret, msglen, "send"))
		return;

	memset(buf, 0, sizeof(buf));

	ret = recv(receiver, buf, msglen, 0);
	if (!ASSERT_EQ(ret, msglen, "recv"))
		return;

	ret = strncmp(buf, msg, msglen);
	if (!ASSERT_EQ(ret, 0, "strncmp"))
		return;
}

static void create_connection(struct test_tcp_custom_syncookie_case *test_case)
{
	int server, client, child;

	server = start_server(test_case->family, test_case->type, test_case->addr, 0, 0);
	if (!ASSERT_NEQ(server, -1, "start_server"))
		return;

	client = connect_to_fd(server, 0);
	if (!ASSERT_NEQ(client, -1, "connect_to_fd"))
		goto close_server;

	child = accept(server, NULL, 0);
	if (!ASSERT_NEQ(child, -1, "accept"))
		goto close_client;

	transfer_message(client, child);
	transfer_message(child, client);

	close(child);
close_client:
	close(client);
close_server:
	close(server);
}

void test_tcp_custom_syncookie(void)
{
	struct test_tcp_custom_syncookie *skel;
	int i;

	if (setup_netns())
		return;

	skel = test_tcp_custom_syncookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (setup_tc(bpf_program__fd(skel->progs.tcp_custom_syncookie)))
		goto destroy_skel;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		if (!test__start_subtest(test_cases[i].name))
			continue;

		skel->bss->handled_syn = false;
		skel->bss->handled_ack = false;

		create_connection(&test_cases[i]);

		ASSERT_EQ(skel->bss->handled_syn, true, "SYN is not handled at tc.");
		ASSERT_EQ(skel->bss->handled_ack, true, "ACK is not handled at tc");
	}

destroy_skel:
	system("tc qdisc del dev lo clsact");
	test_tcp_custom_syncookie__destroy(skel);
}

/* TCP and UDP servers share the same port. The BPF program intercepts
 * the UDP packet, looks up the TCP listener via the dest port, and
 * attempts to assign a TCP reqsk to the UDP skb.
 * Although bpf_sk_assign_tcp_reqsk() assign udp skb to tcp reqsk, the
 * network stack should not crash.
 */
static void run_protocol_check(struct test_tcp_custom_syncookie *skel,
			       int family, const char *addr)
{
	int tcp_server, udp_server, udp_client;
	char buf[] = "test";
	int port, ret;

	tcp_server = start_server(family, SOCK_STREAM, addr, 0, 0);
	if (!ASSERT_NEQ(tcp_server, -1, "start tcp_server"))
		return;

	port = ntohs(get_socket_local_port(tcp_server));

	/* UDP server on same port for synchronization and port sharing */
	udp_server = start_server(family, SOCK_DGRAM, addr, port, 0);
	if (!ASSERT_NEQ(udp_server, -1, "start udp_server"))
		goto close_tcp;

	skel->bss->udp_intercepted = false;

	udp_client = connect_to_fd(udp_server, 0);
	if (!ASSERT_NEQ(udp_client, -1, "connect udp_client"))
		goto close_udp_server;

	ret = send(udp_client, buf, sizeof(buf), 0);
	if (!ASSERT_EQ(ret, sizeof(buf), "send udp"))
		goto close_udp_client;

	memset(buf, 0, sizeof(buf));

	/* recv() ensures TC ingress BPF has processed the skb */
	ret = recv(udp_server, buf, sizeof(buf), 0);
	if (!ASSERT_EQ(ret, sizeof(buf), "recv udp"))
		goto close_udp_client;

	ASSERT_STREQ(buf, "test", "recv data");
	ASSERT_EQ(skel->bss->udp_intercepted, true, "udp_intercepted");

close_udp_client:
	close(udp_client);
close_udp_server:
	close(udp_server);
close_tcp:
	close(tcp_server);
}

void test_tcp_custom_syncookie_protocol_check(void)
{
	struct test_tcp_custom_syncookie *skel;
	int i;

	if (setup_netns())
		return;

	skel = test_tcp_custom_syncookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (setup_tc(bpf_program__fd(skel->progs.tcp_custom_syncookie_badproto)))
		goto destroy_skel;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		if (!test__start_subtest(test_cases[i].name))
			continue;

		run_protocol_check(skel, test_cases[i].family,
				   test_cases[i].addr);
	}

destroy_skel:
	system("tc qdisc del dev lo clsact");
	test_tcp_custom_syncookie__destroy(skel);
}
