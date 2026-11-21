// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Samsung Electronics Co., Ltd. */

#include <test_progs.h>
#include <network_helpers.h>
#include "cgroup_helpers.h"
#include "bpf_tcp_ops_ecn.skel.h"

#define CGROUP_PATH	"/bpf_tcp_ops_ecn"
#define TEST_NETNS	"bpf_tcp_ops_ecn"

/* Must match progs/bpf_tcp_ops_ecn.c */
#define TCP_ECN_MODE_DISABLED	0x00
#define TCP_ECN_MODE_RFC3168	0x01
#define TCP_ECN_MODE_ACCECN	0x10

struct ecn_case {
	const char *name;
	int sysctl_ecn;		/* net.ipv4.tcp_ecn in the test netns */
	int retval_active;	/* ecn_init() return value, active open */
	int retval_passive;	/* ecn_init() return value, passive open */
	__u32 mode_client;	/* expected ECN mode on the client socket */
	__u32 mode_server;	/* expected ECN mode on the accepted socket */
};

/*
 * net.ipv4.tcp_ecn / ecn_init() values (enum tcp_ecn_mode): 0 == no ECN,
 * 1 == accept + request RFC3168 ECN, 3 == accept + request AccECN.
 */
static const struct ecn_case ecn_cases[] = {
	{
		/* The sysctl disables ECN; BPF negotiates RFC3168 ECN. */
		.name = "bpf_enables_classic",
		.sysctl_ecn = 0,
		.retval_active = 1,
		.retval_passive = 1,
		.mode_client = TCP_ECN_MODE_RFC3168,
		.mode_server = TCP_ECN_MODE_RFC3168,
	},
	{
		/* The sysctl disables ECN; BPF negotiates AccECN. */
		.name = "bpf_enables_accecn",
		.sysctl_ecn = 0,
		.retval_active = 3,
		.retval_passive = 3,
		.mode_client = TCP_ECN_MODE_ACCECN,
		.mode_server = TCP_ECN_MODE_ACCECN,
	},
	{
		/*
		 * The client requests AccECN but the server only accepts
		 * RFC3168 ECN (< 3): negotiation degrades to RFC3168.
		 */
		.name = "passive_clamps_accecn",
		.sysctl_ecn = 0,
		.retval_active = 3,
		.retval_passive = 1,
		.mode_client = TCP_ECN_MODE_RFC3168,
		.mode_server = TCP_ECN_MODE_RFC3168,
	},
	{
		/* The server refuses ECN although the sysctl allows it. */
		.name = "passive_refuses_ecn",
		.sysctl_ecn = 1,
		.retval_active = 3,
		.retval_passive = 0,
		.mode_client = TCP_ECN_MODE_DISABLED,
		.mode_server = TCP_ECN_MODE_DISABLED,
	},
	{
		/*
		 * The client does not request ECN although the sysctl
		 * allows it, so there is nothing for the server to accept.
		 */
		.name = "active_disables_ecn",
		.sysctl_ecn = 1,
		.retval_active = 0,
		.retval_passive = 3,
		.mode_client = TCP_ECN_MODE_DISABLED,
		.mode_server = TCP_ECN_MODE_DISABLED,
	},
	{
		/*
		 * Return values above TCP_ECN_IN_ACCECN_OUT_NOECN fall back
		 * to the sysctl on both sides.
		 */
		.name = "fallback_above_range",
		.sysctl_ecn = 1,
		.retval_active = 6,
		.retval_passive = 6,
		.mode_client = TCP_ECN_MODE_RFC3168,
		.mode_server = TCP_ECN_MODE_RFC3168,
	},
	{
		/* Negative return values fall back to the sysctl too. */
		.name = "fallback_negative",
		.sysctl_ecn = 1,
		.retval_active = -1,
		.retval_passive = -1,
		.mode_client = TCP_ECN_MODE_RFC3168,
		.mode_server = TCP_ECN_MODE_RFC3168,
	},
};

/*
 * Connect over loopback and accept() the child socket, so that
 * passive_established is guaranteed to have run: the listener is woken
 * up only after tcp_rcv_state_process() moved the child to established.
 */
static void do_ecn_connect(int family)
{
	const char *addr = family == AF_INET ? "127.0.0.1" : "::1";
	int server_fd, client_fd, accepted_fd;

	server_fd = start_server(family, SOCK_STREAM, addr, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (ASSERT_OK_FD(client_fd, "connect_to_fd")) {
		accepted_fd = accept(server_fd, NULL, NULL);
		if (ASSERT_OK_FD(accepted_fd, "accept"))
			close(accepted_fd);
		close(client_fd);
	}

	close(server_fd);
}

static void test_ecn(int cgroup_fd, struct bpf_tcp_ops_ecn *skel, int family)
{
	struct bpf_link *link;
	char buf[128];
	int i;

	link = bpf_map__attach_cgroup_opts(skel->maps.ecn_ops, cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link, "attach_ecn_ops"))
		return;

	for (i = 0; i < ARRAY_SIZE(ecn_cases); i++) {
		const struct ecn_case *c = &ecn_cases[i];

		snprintf(buf, sizeof(buf), "%d", c->sysctl_ecn);
		if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/tcp_ecn", buf),
			       "write_sysctl_tcp_ecn"))
			break;

		skel->bss->ecn_retval_active = c->retval_active;
		skel->bss->ecn_retval_passive = c->retval_passive;
		skel->bss->ecn_seed_active = -1;
		skel->bss->ecn_seed_passive = -1;
		skel->bss->ecn_active_cnt = 0;
		skel->bss->ecn_passive_cnt = 0;
		skel->bss->ecn_mode_client = 0xdead;
		skel->bss->ecn_mode_server = 0xdead;

		do_ecn_connect(family);

		/* ecn_init() runs once per side per handshake. */
		snprintf(buf, sizeof(buf), "%s: active_cnt", c->name);
		ASSERT_EQ(skel->bss->ecn_active_cnt, 1, buf);
		snprintf(buf, sizeof(buf), "%s: passive_cnt", c->name);
		ASSERT_EQ(skel->bss->ecn_passive_cnt, 1, buf);

		/* bpf_get_retval() must be seeded with the sysctl value. */
		snprintf(buf, sizeof(buf), "%s: seed_active", c->name);
		ASSERT_EQ(skel->bss->ecn_seed_active, c->sysctl_ecn, buf);
		snprintf(buf, sizeof(buf), "%s: seed_passive", c->name);
		ASSERT_EQ(skel->bss->ecn_seed_passive, c->sysctl_ecn, buf);

		snprintf(buf, sizeof(buf), "%s: mode_client", c->name);
		ASSERT_EQ(skel->bss->ecn_mode_client, c->mode_client, buf);
		snprintf(buf, sizeof(buf), "%s: mode_server", c->name);
		ASSERT_EQ(skel->bss->ecn_mode_server, c->mode_server, buf);
	}

	bpf_link__destroy(link);
}

static void run_ecn_subtest(int family)
{
	struct bpf_tcp_ops_ecn *skel = NULL;
	struct netns_obj *ns = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	ns = netns_new(TEST_NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto done;

	skel = bpf_tcp_ops_ecn__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto done;

	test_ecn(cgroup_fd, skel, family);

done:
	bpf_tcp_ops_ecn__destroy(skel);
	netns_free(ns);
	close(cgroup_fd);
}

void test_bpf_tcp_ops_ecn(void)
{
	if (test__start_subtest("ipv4"))
		run_ecn_subtest(AF_INET);
	if (test__start_subtest("ipv6"))
		run_ecn_subtest(AF_INET6);
}
