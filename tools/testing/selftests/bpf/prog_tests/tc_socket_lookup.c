// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * Topology:
 * ---------
 *     NS1 namespace         |   NS2 namespace
 *			     |
 *     +--------------+      |   +--------------+
 *     |    veth01    |----------|    veth10    |
 *     | 172.16.1.100 |      |   | 172.16.1.200 |
 *     |     bpf      |      |   +--------------+
 *     +--------------+      |
 *      server(UDP/TCP)      |
 *  +-------------------+    |
 *  |        vrf1       |    |
 *  |  +--------------+ |    |   +--------------+
 *  |  |    veth02    |----------|    veth20    |
 *  |  | 172.16.2.100 | |    |   | 172.16.2.200 |
 *  |  |     bpf      | |    |   +--------------+
 *  |  +--------------+ |    |
 *  |   server(UDP/TCP) |    |
 *  +-------------------+    |
 *
 * Test flow
 * -----------
 *  The tests verifies that socket lookup via TC is VRF aware:
 *  1) Creates two veth pairs between NS1 and NS2:
 *     a) veth01 <-> veth10 outside the VRF
 *     b) veth02 <-> veth20 in the VRF
 *  2) Attaches to veth01 and veth02 a program that calls:
 *     a) bpf_skc_lookup_tcp() with TCP and tcp_skc is true
 *     b) bpf_sk_lookup_tcp() with TCP and tcp_skc is false
 *     c) bpf_sk_lookup_udp() with UDP
 *     The program stores the lookup result in bss->lookup_status.
 *  3) Creates a socket TCP/UDP server in/outside the VRF.
 *  4) The test expects lookup_status to be:
 *     a) 0 from device in VRF to server outside VRF
 *     b) 0 from device outside VRF to server in VRF
 *     c) 1 from device in VRF to server in VRF
 *     d) 1 from device outside VRF to server outside VRF
 */

#include <net/if.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "tc_socket_lookup.skel.h"

#define NS1 "tc_socket_lookup_1"
#define NS2 "tc_socket_lookup_2"

#define IP4_ADDR_VETH01 "172.16.1.100"
#define IP4_ADDR_VETH10 "172.16.1.200"
#define IP4_ADDR_VETH02 "172.16.2.100"
#define IP4_ADDR_VETH20 "172.16.2.200"

#define NON_VRF_PORT 5000
#define IN_VRF_PORT 5001

#define IO_TIMEOUT_SEC	3

#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			goto fail;				\
	})

#define SYS_NOFAIL(fmt, ...)					\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		system(cmd);					\
	})

static int make_socket(int sotype, const char *ip, int port,
		       struct sockaddr_storage *addr)
{
	struct timeval timeo = { .tv_sec = IO_TIMEOUT_SEC };
	int err, fd;

	err = make_sockaddr(AF_INET, ip, port, addr, NULL);
	if (!ASSERT_OK(err, "make_address"))
		return -1;

	fd = socket(AF_INET, sotype, 0);
	if (!ASSERT_OK(fd < 0, "socket"))
		return -1;

	err = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
	if (!ASSERT_OK(err, "setsockopt(SO_SNDTIMEO)"))
		goto fail;

	err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));
	if (!ASSERT_OK(err, "setsockopt(SO_RCVTIMEO)"))
		goto fail;

	return fd;
fail:
	close(fd);
	return -1;
}

static int make_server(int sotype, const char *ip, int port, const char *ifname)
{
	struct sockaddr_storage addr = {};
	const int one = 1;
	int err, fd = -1;

	fd = make_socket(sotype, ip, port, &addr);
	if (fd < 0)
		return -1;

	if (sotype == SOCK_STREAM) {
		err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
				 sizeof(one));
		if (!ASSERT_OK(err, "setsockopt(SO_REUSEADDR)"))
			goto fail;
	}

	if (ifname) {
		err = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				 ifname, strlen(ifname) + 1);
		if (!ASSERT_OK(err, "setsockopt(SO_BINDTODEVICE)"))
			goto fail;
	}

	err = bind(fd, (void *)&addr, sizeof(struct sockaddr_in));
	if (!ASSERT_OK(err, "bind"))
		goto fail;

	if (sotype == SOCK_STREAM) {
		err = listen(fd, SOMAXCONN);
		if (!ASSERT_OK(err, "listen"))
			goto fail;
	}

	return fd;
fail:
	close(fd);
	return -1;
}

static int attach_tc_prog(struct bpf_tc_hook *hook, int prog_fd)
{
	LIBBPF_OPTS(bpf_tc_opts, opts1, .handle = 1, .priority = 1,
		    .prog_fd = prog_fd);
	int ret;

	ret = bpf_tc_hook_create(hook);
	if (!ASSERT_OK(ret, "create tc hook"))
		return ret;

	if (prog_fd >= 0) {
		hook->attach_point = BPF_TC_INGRESS;
		ret = bpf_tc_attach(hook, &opts1);
		if (!ASSERT_OK(ret, "bpf_tc_attach")) {
			bpf_tc_hook_destroy(hook);
			return ret;
		}
	}
	return 0;
}

static void cleanup(void)
{
	SYS_NOFAIL("test -f /var/run/netns/" NS1 " && ip netns delete "
		   NS1);
	SYS_NOFAIL("test -f /var/run/netns/" NS2 " && ip netns delete "
		   NS2);
}

static int setup(struct tc_socket_lookup *skel)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);
	struct nstoken *nstoken = NULL;
	int ifindex, prog_fd, ret = 0;

	SYS("ip netns add " NS1);
	SYS("ip netns add " NS2);

	/* NS1 <-> NS2 [veth01 <-> veth10] */
	SYS("ip link add veth01 netns " NS1 " type veth peer name veth10 netns "
	    NS2);
	SYS("ip -net " NS1 " addr add " IP4_ADDR_VETH01 "/24 dev veth01");
	SYS("ip -net " NS1 " link set dev veth01 up");
	SYS("ip -net " NS2 " addr add " IP4_ADDR_VETH10 "/24 dev veth10");
	SYS("ip -net " NS2 " link set dev veth10 up");

	/* NS1 <-> NS2 [veth02 <-> veth20] */
	SYS("ip link add veth02 netns " NS1 " type veth peer name veth20 netns "
	    NS2);
	SYS("ip -net " NS1 " addr add " IP4_ADDR_VETH02 "/24 dev veth02");
	SYS("ip -net " NS1 " link set dev veth02 up");
	SYS("ip -net " NS2 " addr add " IP4_ADDR_VETH20 "/24 dev veth20");
	SYS("ip -net " NS2 " link set dev veth20 up");

	/* veth02 -> vrf1  */
	SYS("ip -net " NS1 " link add vrf1 type vrf table 11");
	SYS("ip -net " NS1 " route add vrf vrf1 unreachable default metric "
	    "4278198272");
	SYS("ip -net " NS1 " link set vrf1 alias vrf");
	SYS("ip -net " NS1 " link set vrf1 up");
	SYS("ip -net " NS1 " link set veth02 master vrf1");

	/* Attach prog to veth devices in NS1 */
	nstoken = open_netns(NS1);
	if (!ASSERT_OK_PTR(nstoken, "setns " NS1))
		goto fail;
	prog_fd = bpf_program__fd(skel->progs.test_socket_lookup);
	if (!ASSERT_GE(prog_fd, 0, "bpf_program__fd"))
		goto fail;

	ifindex = if_nametoindex("veth01");
	if (!ASSERT_NEQ(ifindex, 0, "veth01 ifindex"))
		goto fail;
	tc_hook.ifindex = ifindex;
	if (attach_tc_prog(&tc_hook, prog_fd))
		goto fail;

	ifindex = if_nametoindex("veth02");
	if (!ASSERT_NEQ(ifindex, 0, "veth02 ifindex"))
		goto fail;
	tc_hook.ifindex = ifindex;
	if (attach_tc_prog(&tc_hook, prog_fd))
		goto fail;
	goto close;
fail:
	ret = -1;
close:
	if (nstoken)
		close_netns(nstoken);
	return ret;
}

static int test_lookup(struct tc_socket_lookup *skel, int sotype,
		       const char *ip, int port, bool tcp_skc,
		       int lookup_status_exp)
{
	static const char msg[] = "Hello Server";
	struct sockaddr_storage addr = {};
	int fd, ret = 0;

	fd = make_socket(sotype, ip, port, &addr);
	if (fd < 0)
		return -1;

	skel->bss->tcp_skc = tcp_skc;
	skel->bss->lookup_status = -1;

	if (sotype == SOCK_STREAM)
		connect(fd, (void *)&addr, sizeof(struct sockaddr_in));
	else
		sendto(fd, msg, sizeof(msg), 0, (void *)&addr,
		       sizeof(struct sockaddr_in));

	if (!ASSERT_EQ(skel->bss->lookup_status, lookup_status_exp,
		       "lookup_status"))
		goto fail;

	goto close;

fail:
	ret = -1;
close:
	close(fd);
	return ret;
}

static void _test_tc_socket_lookup(struct tc_socket_lookup *skel, int sotype,
				   bool tcp_skc)
{
	int in_vrf_server = -1, non_vrf_server = -1;
	struct nstoken *nstoken = NULL;

	nstoken = open_netns(NS1);
	if (!ASSERT_OK_PTR(nstoken, "setns " NS1))
		goto done;

	/* Open sockets in and outside VRF */
	non_vrf_server = make_server(sotype, "0.0.0.0", NON_VRF_PORT, NULL);
	if (!ASSERT_GE(non_vrf_server, 0, "make_server__outside_vrf_fd"))
		goto done;

	in_vrf_server = make_server(sotype, "0.0.0.0", IN_VRF_PORT, "veth02");
	if (!ASSERT_GE(in_vrf_server, 0, "make_server__in_vrf_fd"))
		goto done;

	/* Perform test from NS2 */
	close_netns(nstoken);
	nstoken = open_netns(NS2);
	if (!ASSERT_OK_PTR(nstoken, "setns " NS2))
		goto done;

	if (!ASSERT_OK(test_lookup(skel, sotype, IP4_ADDR_VETH02, NON_VRF_PORT,
				   tcp_skc, 0), "in_to_out"))
		goto done;
	if (!ASSERT_OK(test_lookup(skel, sotype, IP4_ADDR_VETH02, IN_VRF_PORT,
				   tcp_skc, 1), "in_to_in"))
		goto done;
	if (!ASSERT_OK(test_lookup(skel, sotype, IP4_ADDR_VETH01, NON_VRF_PORT,
				   tcp_skc, 1), "out_to_out"))
		goto done;
	if (!ASSERT_OK(test_lookup(skel, sotype, IP4_ADDR_VETH01, IN_VRF_PORT,
				   tcp_skc, 0), "out_to_in"))
		goto done;

done:
	if (non_vrf_server >= 0)
		close(non_vrf_server);
	if (in_vrf_server >= 0)
		close(in_vrf_server);
	if (nstoken)
		close_netns(nstoken);
}

void test_tc_socket_lookup(void)
{
	struct tc_socket_lookup *skel;

	cleanup();

	skel = tc_socket_lookup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tc_socket_lookup__open_and_load"))
		return;

	if (!ASSERT_OK(setup(skel), "setup"))
		goto done;

	if (test__start_subtest("tc_socket_lookup_tcp"))
		_test_tc_socket_lookup(skel, SOCK_STREAM, false);
	if (test__start_subtest("tc_socket_lookup_tcp_skc"))
		_test_tc_socket_lookup(skel, SOCK_STREAM, true);
	if (test__start_subtest("tc_socket_lookup_udp"))
		_test_tc_socket_lookup(skel, SOCK_DGRAM, false);

done:
	tc_socket_lookup__destroy(skel);
	cleanup();
}
