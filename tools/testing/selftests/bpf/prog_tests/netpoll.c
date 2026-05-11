// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <arpa/inet.h>
#include <net/if.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "netpoll_sanity.skel.h"

#define NS_TEST "netpoll_sanity_ns"
#define NS_TEST_V6 "netpoll_sanity_ns_v6"
#define DUMMY_DEV "dummy0"
#define DUMMY_IP "10.0.0.1"
#define REMOTE_IP "10.0.0.2"
#define DUMMY_IP6 "fd00::1"
#define REMOTE_IP6 "fd00::2"

static void run_netpoll_test(const char *ns_name, const char *local_ip,
			      const char *remote_ip, bool ipv6)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct nstoken *nstoken = NULL;
	struct netpoll_sanity *skel;
	struct in6_addr addr6;
	int err, pfd, fd;

	skel = netpoll_sanity__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		return;

	/* Create a network namespace with a dummy device */
	SYS(fail, "ip netns add %s", ns_name);
	SYS(fail, "ip -net %s link add %s type dummy", ns_name, DUMMY_DEV);
	if (ipv6)
		SYS(fail, "ip -net %s addr add %s/64 dev %s", ns_name, local_ip, DUMMY_DEV);
	else
		SYS(fail, "ip -net %s addr add %s/24 dev %s", ns_name, local_ip, DUMMY_DEV);
	SYS(fail, "ip -net %s link set %s up", ns_name, DUMMY_DEV);

	nstoken = open_netns(ns_name);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto fail;

	/* Configure the BPF program globals */
	snprintf(skel->bss->dev_name, sizeof(skel->bss->dev_name), "%s", DUMMY_DEV);
	if (ipv6) {
		if (inet_pton(AF_INET6, remote_ip, &addr6) != 1)
			goto fail;
		__builtin_memcpy(&skel->bss->remote_ip6, &addr6, sizeof(addr6));
		skel->bss->ipv6 = 1;
	} else {
		skel->bss->remote_ip = inet_addr(remote_ip);
	}
	skel->bss->local_port = 5555;
	skel->bss->remote_port = 6666;
	skel->bss->remote_mac[0] = 0xaa;
	skel->bss->remote_mac[1] = 0xbb;
	skel->bss->remote_mac[2] = 0xcc;
	skel->bss->remote_mac[3] = 0xdd;
	skel->bss->remote_mac[4] = 0xee;
	skel->bss->remote_mac[5] = 0xff;

	/* Step 1: Run the setup SYSCALL prog */
	pfd = bpf_program__fd(skel->progs.netpoll_setup_test);
	if (!ASSERT_GT(pfd, 0, "netpoll_setup_test fd"))
		goto fail;

	err = bpf_prog_test_run_opts(pfd, &opts);
	if (!ASSERT_OK(err, "netpoll_setup_test run"))
		goto fail;

	if (!ASSERT_OK(skel->bss->status, "netpoll_setup_test status"))
		goto fail;

	/* Step 2: Attach the dummy xmit hook */
	skel->links.netpoll_dummy_xmit = bpf_program__attach(skel->progs.netpoll_dummy_xmit);
	if (!ASSERT_OK_PTR(skel->links.netpoll_dummy_xmit, "attach netpoll_dummy_xmit"))
		goto fail;

	/* Step 3: Attach the LSM prog and trigger via file_open */
	skel->links.netpoll_send_test = bpf_program__attach(skel->progs.netpoll_send_test);
	if (!ASSERT_OK_PTR(skel->links.netpoll_send_test, "attach netpoll_send_test"))
		goto fail;

	skel->bss->trigger_send = 1;

	fd = open("/dev/null", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open /dev/null"))
		goto fail;
	close(fd);

	/* send_status should be 0 (NETDEV_TX_OK) -- dummy device accepts
	 * all packets.
	 */
	ASSERT_OK(skel->bss->send_status, "netpoll_send_udp status");
	/* dummy_xmit hooks the dummy driver ndo_start_xmit method called by
	 * netpoll and fetches the UDP payload.
	 */
	ASSERT_STREQ(skel->bss->driver_xmit, skel->data->send_data, "dummy_xmit received");

fail:
	if (nstoken)
		close_netns(nstoken);
	SYS_NOFAIL("ip netns del %s &> /dev/null", ns_name);
	netpoll_sanity__destroy(skel);
}

void test_netpoll_sanity(void)
{
	if (test__start_subtest("ipv4"))
		run_netpoll_test(NS_TEST, DUMMY_IP, REMOTE_IP, false);

	if (test__start_subtest("ipv6"))
		run_netpoll_test(NS_TEST_V6, DUMMY_IP6, REMOTE_IP6, true);
}
