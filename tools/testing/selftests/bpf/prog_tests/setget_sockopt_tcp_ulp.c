// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#define _GNU_SOURCE
#include <net/if.h>

#include "test_progs.h"
#include "network_helpers.h"

#include "setget_sockopt_tcp_ulp.skel.h"

#define CG_NAME "/setget-sockopt-tcp-ulp-test"

static const char addr4_str[] = "127.0.0.1";
static const char addr6_str[] = "::1";
static struct setget_sockopt_tcp_ulp *skel;
static int cg_fd;

static int create_netns(void)
{
	if (!ASSERT_OK(unshare(CLONE_NEWNET), "create netns"))
		return -1;
	if (!ASSERT_OK(system("ip link set dev lo up"), "set lo up"))
		return -1;
	return 0;
}

static int modprobe_tls(void)
{
	if (!ASSERT_OK(system("modprobe tls"), "tls modprobe failed"))
		return -1;
	return 0;
}

static void test_tcp_ulp(int family)
{
	struct setget_sockopt_tcp_ulp__bss *bss = skel->bss;
	int sfd, cfd;

	memset(bss, 0, sizeof(*bss));
	sfd = start_server(family, SOCK_STREAM,
			   family == AF_INET6 ? addr6_str : addr4_str, 0, 0);
	if (!ASSERT_GE(sfd, 0, "start_server"))
		return;

	cfd = connect_to_fd(sfd, 0);
	if (!ASSERT_GE(cfd, 0, "connect_to_fd_server")) {
		close(sfd);
		return;
	}
	close(sfd);
	close(cfd);

	ASSERT_EQ(bss->nr_tcp_ulp, 3, "nr_tcp_ulp");
}

void test_setget_sockopt_tcp_ulp(void)
{
	cg_fd = test__join_cgroup(CG_NAME);
	if (cg_fd < 0)
		return;
	if (create_netns() && modprobe_tls())
		goto done;
	skel = setget_sockopt_tcp_ulp__open();
	if (!ASSERT_OK_PTR(skel, "open skel"))
		goto done;
	if (!ASSERT_OK(setget_sockopt_tcp_ulp__load(skel), "load skel"))
		goto done;
	skel->links.skops_sockopt_tcp_ulp =
		bpf_program__attach_cgroup(skel->progs.skops_sockopt_tcp_ulp, cg_fd);
	if (!ASSERT_OK_PTR(skel->links.skops_sockopt_tcp_ulp, "attach_cgroup"))
		goto done;
	test_tcp_ulp(AF_INET);
	test_tcp_ulp(AF_INET6);
done:
	setget_sockopt_tcp_ulp__destroy(skel);
	close(cg_fd);
}
