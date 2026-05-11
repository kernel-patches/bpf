// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <arpa/inet.h>
#include <net/if.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "netpoll_sanity.skel.h"

#define NS_TEST "netpoll_sanity_ns"
#define DUMMY_DEV "dummy0"
#define DUMMY_IP "10.0.0.1"
#define REMOTE_IP "10.0.0.2"

void test_netpoll_sanity(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct nstoken *nstoken = NULL;
	struct netpoll_sanity *skel;
	int err, pfd, fd;

	skel = netpoll_sanity__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		return;

	/* Create a network namespace with a dummy device */
	SYS(fail, "ip netns add %s", NS_TEST);
	SYS(fail, "ip -net %s link add %s type dummy", NS_TEST, DUMMY_DEV);
	SYS(fail, "ip -net %s addr add %s/24 dev %s", NS_TEST, DUMMY_IP, DUMMY_DEV);
	SYS(fail, "ip -net %s link set %s up", NS_TEST, DUMMY_DEV);

	nstoken = open_netns(NS_TEST);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto fail;

	/* Configure the BPF program globals */
	snprintf(skel->bss->dev_name, sizeof(skel->bss->dev_name), "%s", DUMMY_DEV);
	skel->bss->remote_ip = inet_addr(REMOTE_IP);
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
	SYS_NOFAIL("ip netns del " NS_TEST " &> /dev/null");
	netpoll_sanity__destroy(skel);
}
