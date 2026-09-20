// SPDX-License-Identifier: GPL-2.0-only
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "network_helpers.h"
#include "test_progs.h"
#include "lwt_ip_encap_stale_cb.skel.h"
#include "lwt_ip_encap_stale_cb_freplace.skel.h"
#include "test_lwt_ip_encap.skel.h"

#define BPF_FILE "test_lwt_ip_encap.bpf.o"

#define NETNS_NAME_SIZE	32
#define NETNS_BASE	"ns-lwt-ip-encap"

#define IP4_ADDR_1 "172.16.1.100"
#define IP4_ADDR_2 "172.16.2.100"
#define IP4_ADDR_3 "172.16.3.100"
#define IP4_ADDR_4 "172.16.4.100"
#define IP4_ADDR_5 "172.16.5.100"
#define IP4_ADDR_6 "172.16.6.100"
#define IP4_ADDR_7 "172.16.7.100"
#define IP4_ADDR_8 "172.16.8.100"
#define IP4_ADDR_GRE "172.16.16.100"

#define IP4_ADDR_SRC IP4_ADDR_1
#define IP4_ADDR_DST IP4_ADDR_4

#define IP6_ADDR_1 "fb01::1"
#define IP6_ADDR_2 "fb02::1"
#define IP6_ADDR_3 "fb03::1"
#define IP6_ADDR_4 "fb04::1"
#define IP6_ADDR_5 "fb05::1"
#define IP6_ADDR_6 "fb06::1"
#define IP6_ADDR_7 "fb07::1"
#define IP6_ADDR_8 "fb08::1"
#define IP6_ADDR_GRE "fb10::1"

#define IP4_ADDR_VXLAN  "172.16.17.100"
#define IP6_ADDR_VXLAN  "fb11::1"

#define IP6_ADDR_SRC IP6_ADDR_1
#define IP6_ADDR_DST IP6_ADDR_4

/* Setup/topology:
 *
 *    NS1             NS2             NS3
 *   veth1 <---> veth2   veth3 <---> veth4 (the top route)
 *   veth5 <---> veth6   veth7 <---> veth8 (the bottom route)
 *
 *   Each vethN gets IP[4|6]_ADDR_N address.
 *
 *   IP*_ADDR_SRC = IP*_ADDR_1
 *   IP*_ADDR_DST = IP*_ADDR_4
 *
 *   All tests test pings from IP*_ADDR__SRC to IP*_ADDR_DST.
 *
 *   By default, routes are configured to allow packets to go
 *   IP*_ADDR_1 <=> IP*_ADDR_2 <=> IP*_ADDR_3 <=> IP*_ADDR_4 (the top route).
 *
 *   A GRE device is installed in NS3 with IP*_ADDR_GRE, and
 *   NS1/NS2 are configured to route packets to IP*_ADDR_GRE via IP*_ADDR_8
 *   (the bottom route).
 *
 * Tests:
 *
 *   1. Routes NS2->IP*_ADDR_DST are brought down, so the only way a ping
 *      from IP*_ADDR_SRC to IP*_ADDR_DST can work is via IP*_ADDR_GRE.
 *
 *   2a. In an egress test, a bpf LWT_XMIT program is installed on veth1
 *       that encaps the packets with an IP/GRE header to route to IP*_ADDR_GRE.
 *
 *       ping: SRC->[encap at veth1:egress]->GRE:decap->DST
 *       ping replies go DST->SRC directly
 *
 *   2b. In an ingress test, a bpf LWT_IN program is installed on veth2
 *       that encaps the packets with an IP/GRE header to route to IP*_ADDR_GRE.
 *
 *       ping: SRC->[encap at veth2:ingress]->GRE:decap->DST
 *       ping replies go DST->SRC directly
 */

static int create_ns(char *name, size_t name_sz)
{
	if (!name)
		goto fail;

	if (!ASSERT_OK(append_tid(name, name_sz), "append TID"))
		goto fail;

	SYS(fail, "ip netns add %s", name);

	/* rp_filter gets confused by what these tests are doing, so disable it */
	SYS(fail, "ip netns exec %s sysctl -wq net.ipv4.conf.all.rp_filter=0", name);
	SYS(fail, "ip netns exec %s sysctl -wq net.ipv4.conf.default.rp_filter=0", name);
	/* Disable IPv6 DAD because it sometimes takes too long and fails tests */
	SYS(fail, "ip netns exec %s sysctl -wq net.ipv6.conf.all.accept_dad=0", name);
	SYS(fail, "ip netns exec %s sysctl -wq net.ipv6.conf.default.accept_dad=0", name);

	return 0;
fail:
	return -1;
}

static int set_top_addr(const char *ns1, const char *ns2, const char *ns3)
{
	SYS(fail, "ip -n %s    a add %s/24  dev veth1", ns1, IP4_ADDR_1);
	SYS(fail, "ip -n %s    a add %s/24  dev veth2", ns2, IP4_ADDR_2);
	SYS(fail, "ip -n %s    a add %s/24  dev veth3", ns2, IP4_ADDR_3);
	SYS(fail, "ip -n %s    a add %s/24  dev veth4", ns3, IP4_ADDR_4);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth1", ns1, IP6_ADDR_1);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth2", ns2, IP6_ADDR_2);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth3", ns2, IP6_ADDR_3);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth4", ns3, IP6_ADDR_4);

	SYS(fail, "ip -n %s link set dev veth1 up", ns1);
	SYS(fail, "ip -n %s link set dev veth2 up", ns2);
	SYS(fail, "ip -n %s link set dev veth3 up", ns2);
	SYS(fail, "ip -n %s link set dev veth4 up", ns3);

	return 0;
fail:
	return 1;
}

static int set_bottom_addr(const char *ns1, const char *ns2, const char *ns3)
{
	SYS(fail, "ip -n %s    a add %s/24  dev veth5", ns1, IP4_ADDR_5);
	SYS(fail, "ip -n %s    a add %s/24  dev veth6", ns2, IP4_ADDR_6);
	SYS(fail, "ip -n %s    a add %s/24  dev veth7", ns2, IP4_ADDR_7);
	SYS(fail, "ip -n %s    a add %s/24  dev veth8", ns3, IP4_ADDR_8);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth5", ns1, IP6_ADDR_5);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth6", ns2, IP6_ADDR_6);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth7", ns2, IP6_ADDR_7);
	SYS(fail, "ip -n %s -6 a add %s/128 dev veth8", ns3, IP6_ADDR_8);

	SYS(fail, "ip -n %s link set dev veth5 up", ns1);
	SYS(fail, "ip -n %s link set dev veth6 up", ns2);
	SYS(fail, "ip -n %s link set dev veth7 up", ns2);
	SYS(fail, "ip -n %s link set dev veth8 up", ns3);

	return 0;
fail:
	return 1;
}

static int configure_vrf(const char *ns1, const char *ns2)
{
	if (!ns1 || !ns2)
		goto fail;

	SYS(fail, "ip -n %s link add red type vrf table 1001", ns1);
	SYS(fail, "ip -n %s link set red up", ns1);
	SYS(fail, "ip -n %s route add table 1001 unreachable default metric 8192", ns1);
	SYS(fail, "ip -n %s -6 route add table 1001 unreachable default metric 8192", ns1);
	SYS(fail, "ip -n %s link set veth1 vrf red", ns1);
	SYS(fail, "ip -n %s link set veth5 vrf red", ns1);

	SYS(fail, "ip -n %s link add red type vrf table 1001", ns2);
	SYS(fail, "ip -n %s link set red up", ns2);
	SYS(fail, "ip -n %s route add table 1001 unreachable default metric 8192", ns2);
	SYS(fail, "ip -n %s -6 route add table 1001 unreachable default metric 8192", ns2);
	SYS(fail, "ip -n %s link set veth2 vrf red", ns2);
	SYS(fail, "ip -n %s link set veth3 vrf red", ns2);
	SYS(fail, "ip -n %s link set veth6 vrf red", ns2);
	SYS(fail, "ip -n %s link set veth7 vrf red", ns2);

	return 0;
fail:
	return -1;
}

static int configure_ns1(const char *ns1, const char *vrf)
{
	struct nstoken *nstoken = NULL;

	if (!ns1 || !vrf)
		goto fail;

	nstoken = open_netns(ns1);
	if (!ASSERT_OK_PTR(nstoken, "open ns1"))
		goto fail;

	/* Top route */
	SYS(fail, "ip    route add %s/32  dev veth1 %s", IP4_ADDR_2, vrf);
	SYS(fail, "ip    route add default dev veth1 via %s %s", IP4_ADDR_2, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth1 %s", IP6_ADDR_2, vrf);
	SYS(fail, "ip -6 route add default dev veth1 via %s %s", IP6_ADDR_2, vrf);
	/* Bottom route */
	SYS(fail, "ip    route add %s/32  dev veth5 %s", IP4_ADDR_6, vrf);
	SYS(fail, "ip    route add %s/32  dev veth5 via  %s %s", IP4_ADDR_7, IP4_ADDR_6, vrf);
	SYS(fail, "ip    route add %s/32  dev veth5 via  %s %s", IP4_ADDR_8, IP4_ADDR_6, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth5 %s", IP6_ADDR_6, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth5 via  %s %s", IP6_ADDR_7, IP6_ADDR_6, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth5 via  %s %s", IP6_ADDR_8, IP6_ADDR_6, vrf);

	close_netns(nstoken);
	return 0;
fail:
	close_netns(nstoken);
	return -1;
}

static int configure_ns2(const char *ns2, const char *vrf)
{
	struct nstoken *nstoken = NULL;

	if (!ns2 || !vrf)
		goto fail;

	nstoken = open_netns(ns2);
	if (!ASSERT_OK_PTR(nstoken, "open ns2"))
		goto fail;

	SYS(fail, "ip netns exec %s sysctl -wq net.ipv4.ip_forward=1", ns2);
	SYS(fail, "ip netns exec %s sysctl -wq net.ipv6.conf.all.forwarding=1", ns2);

	/* Top route */
	SYS(fail, "ip    route add %s/32  dev veth2 %s", IP4_ADDR_1, vrf);
	SYS(fail, "ip    route add %s/32  dev veth3 %s", IP4_ADDR_4, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth2 %s", IP6_ADDR_1, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth3 %s", IP6_ADDR_4, vrf);
	/* Bottom route */
	SYS(fail, "ip    route add %s/32  dev veth6 %s", IP4_ADDR_5, vrf);
	SYS(fail, "ip    route add %s/32  dev veth7 %s", IP4_ADDR_8, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth6 %s", IP6_ADDR_5, vrf);
	SYS(fail, "ip -6 route add %s/128 dev veth7 %s", IP6_ADDR_8, vrf);

	close_netns(nstoken);
	return 0;
fail:
	close_netns(nstoken);
	return -1;
}

static int configure_ns3(const char *ns3)
{
	struct nstoken *nstoken = NULL;

	if (!ns3)
		goto fail;

	nstoken = open_netns(ns3);
	if (!ASSERT_OK_PTR(nstoken, "open ns3"))
		goto fail;

	/* Top route */
	SYS(fail, "ip    route add %s/32  dev veth4", IP4_ADDR_3);
	SYS(fail, "ip    route add %s/32  dev veth4 via  %s", IP4_ADDR_1, IP4_ADDR_3);
	SYS(fail, "ip    route add %s/32  dev veth4 via  %s", IP4_ADDR_2, IP4_ADDR_3);
	SYS(fail, "ip -6 route add %s/128 dev veth4", IP6_ADDR_3);
	SYS(fail, "ip -6 route add %s/128 dev veth4 via  %s", IP6_ADDR_1, IP6_ADDR_3);
	SYS(fail, "ip -6 route add %s/128 dev veth4 via  %s", IP6_ADDR_2, IP6_ADDR_3);
	/* Bottom route */
	SYS(fail, "ip    route add %s/32  dev veth8", IP4_ADDR_7);
	SYS(fail, "ip    route add %s/32  dev veth8 via  %s", IP4_ADDR_5, IP4_ADDR_7);
	SYS(fail, "ip    route add %s/32  dev veth8 via  %s", IP4_ADDR_6, IP4_ADDR_7);
	SYS(fail, "ip -6 route add %s/128 dev veth8", IP6_ADDR_7);
	SYS(fail, "ip -6 route add %s/128 dev veth8 via  %s", IP6_ADDR_5, IP6_ADDR_7);
	SYS(fail, "ip -6 route add %s/128 dev veth8 via  %s", IP6_ADDR_6, IP6_ADDR_7);

	/* Configure IPv4 GRE device */
	SYS(fail, "ip tunnel add gre_dev mode gre remote %s local %s ttl 255",
	    IP4_ADDR_1, IP4_ADDR_GRE);
	SYS(fail, "ip link set gre_dev up");
	SYS(fail, "ip a add %s dev gre_dev", IP4_ADDR_GRE);

	/* Configure IPv6 GRE device */
	SYS(fail, "ip tunnel add gre6_dev mode ip6gre remote %s local %s ttl 255",
	    IP6_ADDR_1, IP6_ADDR_GRE);
	SYS(fail, "ip link set gre6_dev up");
	SYS(fail, "ip a add %s dev gre6_dev", IP6_ADDR_GRE);

	close_netns(nstoken);
	return 0;
fail:
	close_netns(nstoken);
	return -1;
}

static int setup_network(char *ns1, char *ns2, char *ns3, const char *vrf)
{
	if (!ns1 || !ns2 || !ns3 || !vrf)
		goto fail;

	SYS(fail, "ip -n %s link add veth1 type veth peer name veth2 netns %s", ns1, ns2);
	SYS(fail, "ip -n %s link add veth3 type veth peer name veth4 netns %s", ns2, ns3);
	SYS(fail, "ip -n %s link add veth5 type veth peer name veth6 netns %s", ns1, ns2);
	SYS(fail, "ip -n %s link add veth7 type veth peer name veth8 netns %s", ns2, ns3);

	if (vrf[0]) {
		if (!ASSERT_OK(configure_vrf(ns1, ns2), "configure vrf"))
			goto fail;
	}
	if (!ASSERT_OK(set_top_addr(ns1, ns2, ns3), "set top addresses"))
		goto fail;

	if (!ASSERT_OK(set_bottom_addr(ns1, ns2, ns3), "set bottom addresses"))
		goto fail;

	if (!ASSERT_OK(configure_ns1(ns1, vrf), "configure ns1 routes"))
		goto fail;

	if (!ASSERT_OK(configure_ns2(ns2, vrf), "configure ns2 routes"))
		goto fail;

	if (!ASSERT_OK(configure_ns3(ns3), "configure ns3 routes"))
		goto fail;

	/* Link bottom route to the GRE tunnels */
	SYS(fail, "ip -n %s route add %s/32 dev veth5 via %s %s",
	    ns1, IP4_ADDR_GRE, IP4_ADDR_6, vrf);
	SYS(fail, "ip -n %s route add %s/32 dev veth7 via %s %s",
	    ns2, IP4_ADDR_GRE, IP4_ADDR_8, vrf);
	SYS(fail, "ip -n %s -6 route add %s/128 dev veth5 via %s %s",
	    ns1, IP6_ADDR_GRE, IP6_ADDR_6, vrf);
	SYS(fail, "ip -n %s -6 route add %s/128 dev veth7 via %s %s",
	    ns2, IP6_ADDR_GRE, IP6_ADDR_8, vrf);

	return 0;
fail:
	return -1;
}

static int remove_routes_to_gredev(const char *ns1, const char *ns2, const char *vrf)
{
	SYS(fail, "ip -n %s route del %s dev veth5 %s", ns1, IP4_ADDR_GRE, vrf);
	SYS(fail, "ip -n %s route del %s dev veth7 %s", ns2, IP4_ADDR_GRE, vrf);
	SYS(fail, "ip -n %s -6 route del %s/128 dev veth5 %s", ns1, IP6_ADDR_GRE, vrf);
	SYS(fail, "ip -n %s -6 route del %s/128 dev veth7 %s", ns2, IP6_ADDR_GRE, vrf);

	return 0;
fail:
	return -1;
}

static int add_unreachable_routes_to_gredev(const char *ns1, const char *ns2, const char *vrf)
{
	SYS(fail, "ip -n %s route add unreachable %s/32 %s", ns1, IP4_ADDR_GRE, vrf);
	SYS(fail, "ip -n %s route add unreachable %s/32 %s", ns2, IP4_ADDR_GRE, vrf);
	SYS(fail, "ip -n %s -6 route add unreachable %s/128 %s", ns1, IP6_ADDR_GRE, vrf);
	SYS(fail, "ip -n %s -6 route add unreachable %s/128 %s", ns2, IP6_ADDR_GRE, vrf);

	return 0;
fail:
	return -1;
}

#define GSO_SIZE 5000
#define GSO_TCP_PORT 9000
/* This tests the fix from commit ea0371f78799 ("net: fix GSO in bpf_lwt_push_ip_encap") */
static int test_gso_fix(const char *ns1, const char *ns3, int family)
{
	const char *ip_addr = family == AF_INET ? IP4_ADDR_DST : IP6_ADDR_DST;
	char gso_packet[GSO_SIZE] = {};
	struct nstoken *nstoken = NULL;
	int sfd, cfd, afd;
	ssize_t bytes;
	int ret = -1;

	if (!ns1 || !ns3)
		return ret;

	nstoken = open_netns(ns3);
	if (!ASSERT_OK_PTR(nstoken, "open ns3"))
		return ret;

	sfd = start_server_str(family, SOCK_STREAM, ip_addr, GSO_TCP_PORT, NULL);
	if (!ASSERT_OK_FD(sfd, "start server"))
		goto close_netns;

	close_netns(nstoken);

	nstoken = open_netns(ns1);
	if (!ASSERT_OK_PTR(nstoken, "open ns1"))
		goto close_server;

	cfd = connect_to_addr_str(family, SOCK_STREAM, ip_addr, GSO_TCP_PORT, NULL);
	if (!ASSERT_OK_FD(cfd, "connect to server"))
		goto close_server;

	close_netns(nstoken);
	nstoken = NULL;

	afd = accept(sfd, NULL, NULL);
	if (!ASSERT_OK_FD(afd, "accept"))
		goto close_client;

	/* Send a packet larger than MTU */
	bytes = send(cfd, gso_packet, GSO_SIZE, 0);
	if (!ASSERT_EQ(bytes, GSO_SIZE, "send packet"))
		goto close_accept;

	/* Verify we received all expected bytes */
	bytes = read(afd, gso_packet, GSO_SIZE);
	if (!ASSERT_EQ(bytes, GSO_SIZE, "receive packet"))
		goto close_accept;

	ret = 0;

close_accept:
	close(afd);
close_client:
	close(cfd);
close_server:
	close(sfd);
close_netns:
	close_netns(nstoken);

	return ret;
}

static int check_ping_ok(const char *ns1)
{
	SYS(fail, "ip netns exec %s ping -c 1 -W1 -I veth1 %s > /dev/null", ns1, IP4_ADDR_DST);
	SYS(fail, "ip netns exec %s %s -c 1 -W1 -I veth1 %s > /dev/null", ns1,
	    ping_command(AF_INET6), IP6_ADDR_DST);
	return 0;
fail:
	return -1;
}

static int check_ping_fails(const char *ns1)
{
	int ret;

	ret = SYS_NOFAIL("ip netns exec %s ping -c 1 -W1 -I veth1 %s", ns1, IP4_ADDR_DST);
	if (!ret)
		return -1;

	ret = SYS_NOFAIL("ip netns exec %s %s -c 1 -W1 -I veth1 %s", ns1,
			 ping_command(AF_INET6), IP6_ADDR_DST);
	if (!ret)
		return -1;

	return 0;
}

#define EGRESS true
#define INGRESS false
#define IPV4_ENCAP true
#define IPV6_ENCAP false
static void lwt_ip_encap(bool ipv4_encap, bool egress, const char *vrf)
{
	char ns1[NETNS_NAME_SIZE] = NETNS_BASE "-1-";
	char ns2[NETNS_NAME_SIZE] = NETNS_BASE "-2-";
	char ns3[NETNS_NAME_SIZE] = NETNS_BASE "-3-";
	char *sec = ipv4_encap ?  "encap_gre" : "encap_gre6";

	if (!vrf)
		return;

	if (!ASSERT_OK(create_ns(ns1, NETNS_NAME_SIZE), "create ns1"))
		goto out;
	if (!ASSERT_OK(create_ns(ns2, NETNS_NAME_SIZE), "create ns2"))
		goto out;
	if (!ASSERT_OK(create_ns(ns3, NETNS_NAME_SIZE), "create ns3"))
		goto out;

	if (!ASSERT_OK(setup_network(ns1, ns2, ns3, vrf), "setup network"))
		goto out;

	/* By default, pings work */
	if (!ASSERT_OK(check_ping_ok(ns1), "ping OK"))
		goto out;

	/* Remove NS2->DST routes, ping fails */
	SYS(out, "ip -n %s    route del %s/32  dev veth3 %s", ns2, IP4_ADDR_DST, vrf);
	SYS(out, "ip -n %s -6 route del %s/128 dev veth3 %s", ns2, IP6_ADDR_DST, vrf);
	if (!ASSERT_OK(check_ping_fails(ns1), "ping expected fail"))
		goto out;

	/* Install replacement routes (LWT/eBPF), pings succeed */
	if (egress) {
		SYS(out, "ip -n %s route add %s encap bpf xmit obj %s sec %s dev veth1 %s",
		    ns1, IP4_ADDR_DST, BPF_FILE, sec, vrf);
		SYS(out, "ip -n %s -6 route add %s encap bpf xmit obj %s sec %s dev veth1 %s",
		    ns1, IP6_ADDR_DST, BPF_FILE, sec, vrf);
	} else {
		SYS(out, "ip -n %s route add %s encap bpf in obj %s sec %s dev veth2 %s",
		    ns2, IP4_ADDR_DST, BPF_FILE, sec, vrf);
		SYS(out, "ip -n %s -6 route add %s encap bpf in obj %s sec %s dev veth2 %s",
		    ns2, IP6_ADDR_DST, BPF_FILE, sec, vrf);
	}

	if (!ASSERT_OK(check_ping_ok(ns1), "ping OK"))
		goto out;

	/* Skip GSO tests with VRF: VRF routing needs properly assigned
	 * source IP/device, which is easy to do with ping but hard with TCP.
	 */
	if (egress && !vrf[0]) {
		if (!ASSERT_OK(test_gso_fix(ns1, ns3, AF_INET), "test GSO"))
			goto out;
	}

	/* Negative test: remove routes to GRE devices: ping fails */
	if (!ASSERT_OK(remove_routes_to_gredev(ns1, ns2, vrf), "remove routes to gredev"))
		goto out;
	if (!ASSERT_OK(check_ping_fails(ns1), "ping expected fail"))
		goto out;

	/* Another negative test */
	if (!ASSERT_OK(add_unreachable_routes_to_gredev(ns1, ns2, vrf),
		       "add unreachable routes"))
		goto out;
	ASSERT_OK(check_ping_fails(ns1), "ping expected fail");

out:
	SYS_NOFAIL("ip netns del %s", ns1);
	SYS_NOFAIL("ip netns del %s", ns2);
	SYS_NOFAIL("ip netns del %s", ns3);
}

void test_lwt_ip_encap_vrf_ipv6(void)
{
	if (test__start_subtest("egress"))
		lwt_ip_encap(IPV6_ENCAP, EGRESS, "vrf red");

	if (test__start_subtest("ingress"))
		lwt_ip_encap(IPV6_ENCAP, INGRESS, "vrf red");
}

void test_lwt_ip_encap_vrf_ipv4(void)
{
	if (test__start_subtest("egress"))
		lwt_ip_encap(IPV4_ENCAP, EGRESS, "vrf red");

	if (test__start_subtest("ingress"))
		lwt_ip_encap(IPV4_ENCAP, INGRESS, "vrf red");
}

void test_lwt_ip_encap_ipv6(void)
{
	if (test__start_subtest("egress"))
		lwt_ip_encap(IPV6_ENCAP, EGRESS, "");

	if (test__start_subtest("ingress"))
		lwt_ip_encap(IPV6_ENCAP, INGRESS, "");
}

void test_lwt_ip_encap_ipv4(void)
{
	if (test__start_subtest("egress"))
		lwt_ip_encap(IPV4_ENCAP, EGRESS, "");

	if (test__start_subtest("ingress"))
		lwt_ip_encap(IPV4_ENCAP, INGRESS, "");
}

/*
 * VxLAN Setup/topology:
 *
 * NS1 (IP*_ADDR_1)                NS2                  NS3 (IP*_ADDR_4)
 *       [ping src]
 *           |                          top route
 *         veth1 (LWT encap)  <<-- veth2        veth3  <<-- veth4 (ping dst)
 *           |                                                ^
 *       (bottom route)                                       | (inner pkt)
 *           v                        bottom route            |
 *         veth5              -->> veth6        veth7  -->> veth8 (vxlan decap)
 *                                                          (IP*_ADDR_VXLAN)
 *
 * Add the VxLAN endpoint addresses to NS3's veth8, create standard
 * VxLAN decap devices bound to those addresses, and install routes so
 * NS1/NS2 can reach the endpoints via the bottom route.  NS2 here is to
 * make sure the LWT-encap VxLAN packets are routed to NS3 correctly.
 */
static int setup_vxlan_routes(const char *ns3, const char *ns1, const char *ns2)
{
	struct nstoken *nstoken;

	nstoken = open_netns(ns3);
	if (!ASSERT_OK_PTR(nstoken, "open ns3 for vxlan"))
		return -1;

	SYS(fail_close, "ip    a add %s/32  dev veth8", IP4_ADDR_VXLAN);
	SYS(fail_close, "ip -6 a add %s/128 dev veth8", IP6_ADDR_VXLAN);
	/*
	 * Standard VxLAN devices to decap the encapsulated packets.  The inner
	 * Ethernet frame uses a broadcast dst MAC so the IP stack accepts it
	 * without ARP or FDB configuration.
	 */
	SYS(fail_close, "ip link add vxlan4 type vxlan id 1 dstport 4789 local %s dev veth8 nolearning noudpcsum",
	    IP4_ADDR_VXLAN);
	SYS(fail_close, "ip link set vxlan4 up");
	SYS(fail_close, "ip link add vxlan6 type vxlan id 1 dstport 4789 local %s dev veth8 nolearning udp6zerocsumrx",
	    IP6_ADDR_VXLAN);
	SYS(fail_close, "ip link set vxlan6 up");
	close_netns(nstoken);

	SYS(fail, "ip -n %s    route add %s/32  dev veth5 via %s",
	    ns1, IP4_ADDR_VXLAN, IP4_ADDR_6);
	SYS(fail, "ip -n %s    route add %s/32  dev veth7 via %s",
	    ns2, IP4_ADDR_VXLAN, IP4_ADDR_8);
	SYS(fail, "ip -n %s -6 route add %s/128 dev veth5 via %s",
	    ns1, IP6_ADDR_VXLAN, IP6_ADDR_6);
	SYS(fail, "ip -n %s -6 route add %s/128 dev veth7 via %s",
	    ns2, IP6_ADDR_VXLAN, IP6_ADDR_8);
	return 0;

fail_close:
	close_netns(nstoken);
fail:
	return -1;
}

static void lwt_ip_encap_vxlan(bool ipv4_encap)
{
	char ns1[NETNS_NAME_SIZE] = NETNS_BASE "-1-";
	char ns2[NETNS_NAME_SIZE] = NETNS_BASE "-2-";
	char ns3[NETNS_NAME_SIZE] = NETNS_BASE "-3-";
	const char *sec = ipv4_encap ? "encap_vxlan" : "encap_vxlan6";
	int expected_offset = ipv4_encap ? (int)sizeof(struct iphdr)
					 : (int)sizeof(struct ipv6hdr);
	struct test_lwt_ip_encap *skel = NULL;
	int thdr_offset, err;

	if (!ASSERT_OK(create_ns(ns1, NETNS_NAME_SIZE), "create ns1"))
		goto out;
	if (!ASSERT_OK(create_ns(ns2, NETNS_NAME_SIZE), "create ns2"))
		goto out;
	if (!ASSERT_OK(create_ns(ns3, NETNS_NAME_SIZE), "create ns3"))
		goto out;

	if (!ASSERT_OK(setup_network(ns1, ns2, ns3, ""), "setup network"))
		goto out;

	if (!ASSERT_OK(setup_vxlan_routes(ns3, ns1, ns2), "setup vxlan routes"))
		goto out;

	skel = test_lwt_ip_encap__open();
	if (!ASSERT_OK_PTR(skel, "test_lwt_ip_encap__open"))
		goto out;

	bpf_program__set_autoload(skel->progs.bpf_lwt_encap_gre, false);
	bpf_program__set_autoload(skel->progs.bpf_lwt_encap_gre6, false);
	bpf_program__set_autoload(skel->progs.bpf_lwt_encap_vxlan, false);
	bpf_program__set_autoload(skel->progs.bpf_lwt_encap_vxlan6, false);
	bpf_program__set_autoload(skel->progs.fexit_lwt_push_ip_encap, true);
	skel->rodata->tgt_ip_version = ipv4_encap ? 4 : 6;

	err = test_lwt_ip_encap__load(skel);
	if (!ASSERT_OK(err, "test_lwt_ip_encap__load"))
		goto out;

	err = test_lwt_ip_encap__attach(skel);
	if (!ASSERT_OK(err, "test_lwt_ip_encap__attach"))
		goto out;

	/* Remove the direct NS2->DST route so packets must go via LWT encap. */
	SYS(out, "ip -n %s    route del %s/32  dev veth3", ns2, IP4_ADDR_DST);
	SYS(out, "ip -n %s -6 route del %s/128 dev veth3", ns2, IP6_ADDR_DST);

	if (ipv4_encap)
		SYS(out, "ip -n %s route add %s encap bpf xmit obj %s sec %s dev veth1",
		    ns1, IP4_ADDR_DST, BPF_FILE, sec);
	else
		SYS(out, "ip -n %s -6 route add %s encap bpf xmit obj %s sec %s dev veth1",
		    ns1, IP6_ADDR_DST, BPF_FILE, sec);

	skel->bss->fexit_triggered = false;

	if (ipv4_encap)
		SYS(out, "ip netns exec %s ping -c 1 -W1 %s", ns1, IP4_ADDR_DST);
	else
		SYS(out, "ip netns exec %s %s -c 1 -W1 %s", ns1,
		    ping_command(AF_INET6), IP6_ADDR_DST);

	if (!ASSERT_TRUE(skel->bss->fexit_triggered, "fexit_triggered"))
		goto out;

	thdr_offset = (int)skel->bss->transport_hdr - (int)skel->bss->network_hdr;
	ASSERT_EQ(thdr_offset, expected_offset, "transport_hdr offset");

out:
	test_lwt_ip_encap__destroy(skel);
	SYS_NOFAIL("ip netns del %s", ns1);
	SYS_NOFAIL("ip netns del %s", ns2);
	SYS_NOFAIL("ip netns del %s", ns3);
}

void test_lwt_ip_encap_vxlan_ipv4(void)
{
	lwt_ip_encap_vxlan(IPV4_ENCAP);
}

void test_lwt_ip_encap_vxlan_ipv6(void)
{
	lwt_ip_encap_vxlan(IPV6_ENCAP);
}

#define STALE_CB_NETNS "lwt-ip-encap-stale-cb"
#define STALE_CB_DST "10.9.9.0/24"
#define STALE_CB_PIN_FMT "/sys/fs/bpf/lwt_ip_encap_stale_cb_%d"
#define STALE_CB_PKT_LEN 64

static __u16 stale_cb_csum(const void *data, size_t len)
{
	const __u16 *word = data;
	__u32 sum = 0;

	while (len > 1) {
		sum += *word++;
		len -= sizeof(*word);
	}
	if (len)
		sum += *(const __u8 *)word;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static int stale_cb_get_mac(const char *ifname, __u8 mac[ETH_ALEN])
{
	struct ifreq ifr = {};
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		int err = -errno;

		close(fd);
		return err;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(fd);
	return 0;
}

static int stale_cb_open_packet_socket(int ifindex)
{
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = ifindex,
	};
	struct timeval timeout = { .tv_sec = 2 };
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return -errno;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		int err = -errno;

		close(fd);
		return err;
	}

	return fd;
}

static int stale_cb_send_packet(int fd, const __u8 src_mac[ETH_ALEN],
				const __u8 dst_mac[ETH_ALEN])
{
	__u8 frame[ETH_HLEN + STALE_CB_PKT_LEN] = {};
	struct ethhdr *eth = (struct ethhdr *)frame;
	struct iphdr *iph = (struct iphdr *)(frame + ETH_HLEN);
	__u8 *opt = (__u8 *)(iph + 1);

	memcpy(eth->h_source, src_mac, ETH_ALEN);
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	iph->version = 4;
	iph->ihl = 7;
	iph->tos = 8;
	iph->tot_len = htons(STALE_CB_PKT_LEN);
	iph->id = htons(0x1234);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = inet_addr("10.0.0.2");
	iph->daddr = inet_addr("10.9.9.9");
	opt[0] = IPOPT_RR;
	opt[1] = 8;
	opt[2] = 4;
	iph->check = stale_cb_csum(iph, iph->ihl * 4);

	memset(frame + ETH_HLEN + iph->ihl * 4, 0x41,
	       STALE_CB_PKT_LEN - iph->ihl * 4);
	if (send(fd, frame, sizeof(frame), 0) != sizeof(frame))
		return -errno;

	return 0;
}

static int stale_cb_icmp_ihl(int fd, __u32 *saddr)
{
	__u8 packet[512];
	ssize_t len;

	while ((len = recv(fd, packet, sizeof(packet), 0)) >= 0) {
		const struct ethhdr *eth = (const struct ethhdr *)packet;
		const struct iphdr *iph;
		const struct icmphdr *icmph;
		size_t ip_len;

		if (len < ETH_HLEN + sizeof(*iph) ||
		    eth->h_proto != htons(ETH_P_IP))
			continue;
		iph = (const struct iphdr *)(packet + ETH_HLEN);
		ip_len = iph->ihl * 4;
		if (iph->ihl < 5 || len < ETH_HLEN + ip_len + sizeof(*icmph) ||
		    iph->protocol != IPPROTO_ICMP)
			continue;
		icmph = (const struct icmphdr *)((const __u8 *)iph + ip_len);
		if (icmph->type == ICMP_TIME_EXCEEDED) {
			*saddr = iph->saddr;
			return iph->ihl;
		}
	}

	return -errno;
}

static void lwt_ip_encap_stale_cb(bool use_freplace, bool use_vrf,
				  bool pre_encap)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		    .attach_point = BPF_TC_INGRESS,
		   );
	LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		    .handle = 1,
		    .priority = 1,
		   );
	struct lwt_ip_encap_stale_cb_freplace *freplace_skel = NULL;
	struct lwt_ip_encap_stale_cb *skel = NULL;
	struct bpf_program *target, *replacement;
	struct bpf_link *freplace_link = NULL;
	struct netns_obj *netns = NULL;
	char pin_path[128];
	__u8 mac0[ETH_ALEN], mac1[ETH_ALEN];
	__u32 saddr = 0;
	bool tc_hook_created = false;
	int ifindex, packet_fd = -1, prog_fd, err, ihl;

	skel = lwt_ip_encap_stale_cb__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load target"))
		goto out;
	target = use_freplace ? skel->progs.lwt_in_freplace_target :
				  skel->progs.lwt_in_direct;
	prog_fd = bpf_program__fd(target);

	if (use_freplace) {
		freplace_skel = lwt_ip_encap_stale_cb_freplace__open();
		if (!ASSERT_OK_PTR(freplace_skel, "open freplace"))
			goto out;
		replacement = freplace_skel->progs.replace_add_ip_encap;
		err = bpf_program__set_attach_target(replacement, prog_fd,
						     "add_ip_encap");
		if (!ASSERT_OK(err, "set freplace target"))
			goto out;
		err = lwt_ip_encap_stale_cb_freplace__load(freplace_skel);
		if (!ASSERT_OK(err, "load freplace"))
			goto out;
		freplace_link = bpf_program__attach_freplace(replacement, prog_fd,
							     "add_ip_encap");
		if (!ASSERT_OK_PTR(freplace_link, "attach freplace"))
			goto out;
	}

	snprintf(pin_path, sizeof(pin_path), STALE_CB_PIN_FMT, getpid());
	unlink(pin_path);
	err = bpf_program__pin(target, pin_path);
	if (!ASSERT_OK(err, "pin target"))
		goto out;

	netns = netns_new(STALE_CB_NETNS, true);
	if (!ASSERT_OK_PTR(netns, "create netns"))
		goto out_unpin;

	SYS(out_netns, "ip link add vh0 type veth peer name vh1");
	if (use_vrf) {
		SYS(out_netns, "ip link add vrf0 type vrf table 1001");
		SYS(out_netns, "ip link set vrf0 up");
		SYS(out_netns, "ip link set vh1 master vrf0");
		SYS(out_netns, "ip addr add 10.1.0.1/32 dev vrf0");
		SYS(out_netns, "sysctl -wq net.ipv4.conf.vrf0.rp_filter=0");
		SYS(out_netns, "sysctl -wq net.ipv4.icmp_errors_use_inbound_ifaddr=1");
	}
	SYS(out_netns, "ip link set vh0 up");
	SYS(out_netns, "ip link set vh1 up");
	SYS(out_netns, "ip addr add 10.0.0.1/24 dev vh1");
	SYS(out_netns, "sysctl -wq net.ipv4.ip_forward=1");
	SYS(out_netns, "sysctl -wq net.ipv4.conf.all.rp_filter=0");
	SYS(out_netns, "sysctl -wq net.ipv4.conf.vh1.rp_filter=0");
	SYS(out_netns, "sysctl -wq net.ipv4.conf.all.accept_local=1");

	if (pre_encap) {
		tc_hook.ifindex = if_nametoindex("vh1");
		if (!ASSERT_GT(tc_hook.ifindex, 0, "vh1 ifindex"))
			goto out_netns;
		err = bpf_tc_hook_create(&tc_hook);
		if (!ASSERT_OK(err, "create vh1 ingress hook"))
			goto out_netns;
		tc_hook_created = true;
		tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_pre_encap);
		err = bpf_tc_attach(&tc_hook, &tc_opts);
		if (!ASSERT_OK(err, "attach pre-encapsulation program"))
			goto out_netns;
	}

	if (!ASSERT_OK(stale_cb_get_mac("vh0", mac0), "get vh0 mac") ||
	    !ASSERT_OK(stale_cb_get_mac("vh1", mac1), "get vh1 mac"))
		goto out_netns;
	SYS(out_netns,
	    "ip neigh replace 10.0.0.2 lladdr %02x:%02x:%02x:%02x:%02x:%02x nud permanent dev vh1",
	    mac0[0], mac0[1], mac0[2], mac0[3], mac0[4], mac0[5]);
	SYS(out_netns,
	    "ip route add %s encap bpf in pinned %s via 10.0.0.2 dev vh1 %s",
	    STALE_CB_DST, pin_path, use_vrf ? "vrf vrf0" : "");

	ifindex = if_nametoindex("vh0");
	if (!ASSERT_GT(ifindex, 0, "vh0 ifindex"))
		goto out_netns;
	packet_fd = stale_cb_open_packet_socket(ifindex);
	if (!ASSERT_OK_FD(packet_fd, "open packet socket"))
		goto out_netns;
	if (!ASSERT_OK(stale_cb_send_packet(packet_fd, mac0, mac1),
		       "send crafted packet"))
		goto out_netns;

	ihl = stale_cb_icmp_ihl(packet_fd, &saddr);
	if (!ASSERT_EQ(ihl, 5, "ICMP IPv4 header length"))
		goto out_netns;
	if (use_vrf && !ASSERT_EQ(saddr, inet_addr("10.0.0.1"),
				  "ICMP source is ingress slave address"))
		goto out_netns;
	if (use_freplace) {
		ASSERT_TRUE(freplace_skel->bss->freplace_ran, "freplace ran");
		ASSERT_TRUE(freplace_skel->bss->freplace_cb_zero,
			    "freplace cb was cleared");
	} else {
		ASSERT_TRUE(skel->bss->direct_ran, "direct program ran");
		ASSERT_TRUE(skel->bss->direct_cb_zero, "direct cb was cleared");
	}

out_netns:
	if (packet_fd >= 0)
		close(packet_fd);
	if (tc_hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	netns_free(netns);
out_unpin:
	unlink(pin_path);
out:
	bpf_link__destroy(freplace_link);
	lwt_ip_encap_stale_cb_freplace__destroy(freplace_skel);
	lwt_ip_encap_stale_cb__destroy(skel);
}

void test_lwt_ip_encap_stale_cb(void)
{
	if (test__start_subtest("direct-cb-access"))
		lwt_ip_encap_stale_cb(false, false, false);
	if (test__start_subtest("freplace-cb-access"))
		lwt_ip_encap_stale_cb(true, false, false);
	if (test__start_subtest("vrf-direct-cb-access"))
		lwt_ip_encap_stale_cb(false, true, false);
	if (test__start_subtest("vrf-freplace-cb-access"))
		lwt_ip_encap_stale_cb(true, true, false);
	if (test__start_subtest("already-encapsulated"))
		lwt_ip_encap_stale_cb(false, false, true);
}
