// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Setup/topology:
 *
 *    NS1             NS2             NS3
 *   veth1 <---> veth2   veth3 <---> veth4 (the top route)
 *   veth5 <---> veth6   veth7 <---> veth8 (the bottom route)
 *
 *   each vethN gets IP[4|6]_N address
 *
 *   IP*_SRC = IP*_1
 *   IP*_DST = IP*_4
 *
 *   all tests test pings from IP*_SRC to IP*_DST
 *
 *   by default, routes are configured to allow packets to go
 *   IP*_1 <=> IP*_2 <=> IP*_3 <=> IP*_4 (the top route)
 *
 *   a GRE device is installed in NS3 with IP*_GRE, and
 *   NS1/NS2 are configured to route packets to IP*_GRE via IP*_8
 *   (the bottom route)
 *
 * Tests:
 *
 *   1. routes NS2->IP*_DST are brought down, so the only way a ping
 *      from IP*_SRC to IP*_DST can work is via IP*_GRE
 *
 *   2a. in an egress test, a bpf LWT_XMIT program is installed on veth1
 *       that encaps the packets with an IP/GRE header to route to IP*_GRE
 *
 *       ping: SRC->[encap at veth1:egress]->GRE:decap->DST
 *       ping replies go DST->SRC directly
 *
 *   2b. in an ingress test, a bpf LWT_IN program is installed on veth2
 *       that encaps the packets with an IP/GRE header to route to IP*_GRE
 *
 *       ping: SRC->[encap at veth2:ingress]->GRE:decap->DST
 *       ping replies go DST->SRC directly
 *
 *   2c. in an egress_md test, a bpf LWT_XMIT program is installed on a
 *       route towards collect_md gre{,6} devices in NS1 and sets the tunnel
 *       key such that packets are encapsulated with an IP/GRE header to route
 *       to IP*_GRE
 *
 *       ping: SRC->[encap at gre{,6}_md:xmit]->GRE:decap->DST
 *       ping replies go DST->SRC directly
 */

#include "test_progs.h"
#include "network_helpers.h"

#define NS_1 "ns_lwt_1"
#define NS_2 "ns_lwt_2"
#define NS_3 "ns_lwt_3"

#define IP4_1 "172.16.1.100"
#define IP4_2 "172.16.2.100"
#define IP4_3 "172.16.3.100"
#define IP4_4 "172.16.4.100"
#define IP4_5 "172.16.5.100"
#define IP4_6 "172.16.6.100"
#define IP4_7 "172.16.7.100"
#define IP4_8 "172.16.8.100"
#define IP4_GRE "172.16.16.100"
#define IP4_DST IP4_4

#define IP6_1 "fb01::1"
#define IP6_2 "fb02::1"
#define IP6_3 "fb03::1"
#define IP6_4 "fb04::1"
#define IP6_5 "fb05::1"
#define IP6_6 "fb06::1"
#define IP6_7 "fb07::1"
#define IP6_8 "fb08::1"
#define IP6_GRE "fb10::1"
#define IP6_DST IP6_4

#define TEST_VRF_NAME "red"

static const char * const namespaces[] = {NS_1, NS_2, NS_3, NULL};
static __u32 duration;
static bool use_vrf;

enum encap_type {
	ENCAP_EGRESS,
	ENCAP_INGRESS,
	ENCAP_EGRESS_MD,
};

#define SYS(fmt, ...)							\
	({								\
		char cmd[1024];						\
		snprintf(cmd, sizeof(cmd), fmt,	##__VA_ARGS__);		\
		if (!ASSERT_OK(system(cmd), cmd))			\
			goto fail;					\
	})

#define ADD_VETH_PAIR(v1, ns1, v2, ns2)					\
	SYS("ip link add " v1 " netns " ns1 " type veth "		\
	    "peer name " v2 " netns " ns2)

#define SET_NS_ROUTE(op, netns, family, fmt, ...)			\
	SYS("ip %s%s %s route " op " %s " fmt,				\
	    netns[0] ? "-netns " : "", netns[0] ? netns : "",		\
	    family == AF_INET6 ? "-6" : "",				\
	    use_vrf ? "vrf " TEST_VRF_NAME : "",			\
	    ##__VA_ARGS__)

#define SET_NS_ADDR_ROUTE(op, netns, addr, fmt, ...)			\
	({								\
		int family = strchr(addr, ':') ? AF_INET6 : AF_INET;	\
		SET_NS_ROUTE(op, netns, family, addr "%s " fmt,		\
			     family == AF_INET6 ? "/128" : "/32",	\
			     ##__VA_ARGS__);				\
	})

#define ADD_ROUTE(family, ...) SET_NS_ROUTE("add", "", family, ##__VA_ARGS__)

#define ADD_ADDR_ROUTE(...) SET_NS_ADDR_ROUTE("add", "", ##__VA_ARGS__)

static int write_sysctl(const char *sysctl, const char *value)
{
	int fd, err, len;

	fd = open(sysctl, O_WRONLY);
	if (CHECK(fd == -1, "open sysctl", "open(%s): %s (%d)\n",
		  sysctl, strerror(errno), errno))
		return -1;

	len = strlen(value);
	err = write(fd, value, len);
	close(fd);
	if (CHECK(err != len, "write sysctl",
		  "write(%s, %s): err:%d %s (%d)\n",
		  sysctl, value, err, strerror(errno), errno))
		return -1;

	return 0;
}

static int setup_namespaces(const char *verb)
{
	const char * const *ns = namespaces;

	while (*ns) {
		SYS("ip netns %s %s", verb, *ns);
		ns++;
	}
	return 0;
fail:
	return -1;
}

static void setup_namespaces_nofail(const char *verb)
{
	const char * const *ns = namespaces;
	char cmd[128];

	while (*ns) {
		snprintf(cmd, sizeof(cmd), "ip netns %s %s > /dev/null 2>&1",
			 verb, *ns);
		system(cmd);
		ns++;
	}
}

static int setup_ns(const char *ns, int (*ns_setup_fn)(void))
{
	struct nstoken *nstoken;
	int err = -1;

	nstoken = open_netns(ns);
	if (!ASSERT_OK_PTR(nstoken, "setns"))
		return -1;

	/* rp_filter gets confused by what these tests are doing,
	 * so disable it.
	 * also disable IPv6 DAD because it sometimes takes too long and fails
	 * tests.
	 */
	if (write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0") ||
	    write_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0") ||
	    write_sysctl("/proc/sys/net/ipv6/conf/all/accept_dad", "0") ||
	    write_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0"))
		goto exit;

	err = ns_setup_fn();

exit:
	close_netns(nstoken);
	return err;
}

static int setup_device(const char *devname, const char *addr4,
			const char *addr6)
{
	if (use_vrf)
		SYS("ip link set %s vrf %s", devname, TEST_VRF_NAME);

	if (addr4)
		SYS("ip addr add %s/24 dev %s", addr4, devname);

	if (addr6)
		SYS("ip -6 addr add %s/128 nodad dev %s", addr6, devname);

	SYS("ip link set dev %s up", devname);
	return 0;
fail:
	return -1;
}

static int setup_vrf(void)
{
	SYS("ip link add %s type vrf table 1001", TEST_VRF_NAME);
	SYS("ip link set dev %s up", TEST_VRF_NAME);
	SYS("ip route add table 1001 unreachable default metric 8192");
	SYS("ip -6 route add table 1001 unreachable default metric 8192");
	return 0;
fail:
	return -1;
}

static int setup_ns1(void)
{
	if (use_vrf && setup_vrf())
		goto fail;

	SYS("ip link add gre_md type gre external");
	SYS("ip link add gre6_md type ip6gre external");

	if (setup_device("veth1", IP4_1, IP6_1) ||
	    setup_device("veth5", IP4_5, IP6_5) ||
	    setup_device("gre_md", IP4_1, IP6_1) ||
	    setup_device("gre6_md", IP4_1, IP6_1))
		goto fail;

	/* Top route */
	ADD_ADDR_ROUTE(IP4_2, "dev veth1");
	ADD_ADDR_ROUTE(IP6_2, "dev veth1");
	ADD_ROUTE(AF_INET, "default dev veth1 via " IP4_2);
	ADD_ROUTE(AF_INET6, "default dev veth1 via " IP6_2);

	/* Bottom route */
	ADD_ADDR_ROUTE(IP4_6, "dev veth5");
	ADD_ADDR_ROUTE(IP4_7, "dev veth5 via " IP4_6);
	ADD_ADDR_ROUTE(IP4_8, "dev veth5 via " IP4_6);
	ADD_ADDR_ROUTE(IP6_6, "dev veth5");
	ADD_ADDR_ROUTE(IP6_7, "dev veth5 via " IP6_6);
	ADD_ADDR_ROUTE(IP6_8, "dev veth5 via " IP6_6);

	/* GRE peer via the bottom route */
	ADD_ADDR_ROUTE(IP4_GRE, "dev veth5 via " IP4_6);
	ADD_ADDR_ROUTE(IP6_GRE, "dev veth5 via " IP6_6);
	return 0;
fail:
	return -1;
}

static int setup_ns2(void)
{
	if (write_sysctl("/proc/sys/net/ipv4/ip_forward", "1") ||
	    write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1"))
		goto fail;

	if (use_vrf && setup_vrf())
		goto fail;

	if (setup_device("veth2", IP4_2, IP6_2) ||
	    setup_device("veth3", IP4_3, IP6_3) ||
	    setup_device("veth6", IP4_6, IP6_6) ||
	    setup_device("veth7", IP4_7, IP6_7))
		goto fail;

	/* Top route */
	ADD_ADDR_ROUTE(IP4_1, "dev veth2");
	ADD_ADDR_ROUTE(IP4_4, "dev veth3");
	ADD_ADDR_ROUTE(IP6_1, "dev veth2");
	ADD_ADDR_ROUTE(IP6_4, "dev veth3");

	/* Bottom route */
	ADD_ADDR_ROUTE(IP4_5, "dev veth6");
	ADD_ADDR_ROUTE(IP4_8, "dev veth7");
	ADD_ADDR_ROUTE(IP6_5, "dev veth6");
	ADD_ADDR_ROUTE(IP6_8, "dev veth7");

	/* GRE peer via the bottom route */
	ADD_ADDR_ROUTE(IP4_GRE, "dev veth7 via " IP4_8);
	ADD_ADDR_ROUTE(IP6_GRE, "dev veth7 via " IP6_8);
	return 0;
fail:
	return -1;
}

static int setup_ns3(void)
{
	if (use_vrf && setup_vrf())
		goto fail;

	if (setup_device("veth4", IP4_4, IP6_4) ||
	    setup_device("veth8", IP4_8, IP6_8))
		goto fail;

	/* Top route */
	ADD_ADDR_ROUTE(IP4_3, "dev veth4");
	ADD_ADDR_ROUTE(IP4_1, "dev veth4 via " IP4_3);
	ADD_ADDR_ROUTE(IP4_2, "dev veth4 via " IP4_3);
	ADD_ADDR_ROUTE(IP6_3, "dev veth4");
	ADD_ADDR_ROUTE(IP6_1, "dev veth4 via " IP6_3);
	ADD_ADDR_ROUTE(IP6_2, "dev veth4 via " IP6_3);

	/* Bottom route */
	ADD_ADDR_ROUTE(IP4_7, "dev veth8");
	ADD_ADDR_ROUTE(IP4_5, "dev veth8 via " IP4_7);
	ADD_ADDR_ROUTE(IP4_6, "dev veth8 via " IP4_7);
	ADD_ADDR_ROUTE(IP6_7, "dev veth8");
	ADD_ADDR_ROUTE(IP6_5, "dev veth8 via " IP6_7);
	ADD_ADDR_ROUTE(IP6_6, "dev veth8 via " IP6_7);

	/* configure IPv4 GRE device in NS3, and a route to it via the
	 * "bottom" route
	 */
	SYS("ip tunnel add gre_dev mode gre remote " IP4_5 " local " IP4_GRE
	    " ttl 255 key 0");
	if (setup_device("gre_dev", IP4_GRE, NULL))
		goto fail;

	SYS("ip tunnel add gre6_dev mode ip6gre remote " IP6_5 " local " IP6_GRE
	    " ttl 255 key 0");
	if (setup_device("gre6_dev", NULL, IP6_GRE))
		goto fail;

	return 0;
fail:
	return -1;
}

static int setup_links_and_routes(void)
{
	ADD_VETH_PAIR("veth1", NS_1, "veth2", NS_2);
	ADD_VETH_PAIR("veth3", NS_2, "veth4", NS_3);
	ADD_VETH_PAIR("veth5", NS_1, "veth6", NS_2);
	ADD_VETH_PAIR("veth7", NS_2, "veth8", NS_3);

	if (setup_ns(NS_1, setup_ns1) ||
	    setup_ns(NS_2, setup_ns2) ||
	    setup_ns(NS_3, setup_ns3))
		goto fail;

	return 0;
fail:
	return -1;
}

static int remove_routes_to_gredev(void)
{
	SET_NS_ADDR_ROUTE("del", NS_1, IP4_GRE, "dev veth5");
	SET_NS_ADDR_ROUTE("del", NS_1, IP6_GRE, "dev veth5");
	SET_NS_ADDR_ROUTE("del", NS_2, IP4_GRE, "dev veth7");
	SET_NS_ADDR_ROUTE("del", NS_2, IP6_GRE, "dev veth7");
fail:
	return -1;
}

static int add_unreachable_routes_to_gredev(void)
{
	SET_NS_ROUTE("add", NS_1, AF_INET, "unreachable " IP4_GRE "/32");
	SET_NS_ROUTE("add", NS_1, AF_INET6, "unreachable " IP6_GRE "/128");
	SET_NS_ROUTE("add", NS_2, AF_INET, "unreachable " IP4_GRE "/32");
	SET_NS_ROUTE("add", NS_2, AF_INET6, "unreachable " IP6_GRE "/128");
	return 0;
fail:
	return -1;
}

static int test_ping(int family, bool must_fail, bool bindtodev)
{
	const char *addr, *ping_args;
	char cmd[1024];
	int ret;

	addr = family == AF_INET ? IP4_DST : IP6_DST;
	ping_args = bindtodev ? "-c 1 -W 1 -I veth1" : "-c 1 -W 1";
	snprintf(cmd, sizeof(cmd),
		 "ip netns exec " NS_1 " %s %s %s > /dev/null",
		 ping_command(family), ping_args, addr);
	ret = system(cmd);
	if (!ASSERT_EQ(!!ret, !!must_fail, cmd))
		return -1;
	return 0;
}

#define TIMEOUT_MILLIS 10000

static int test_gso(int family, const char *dst)
{
	int listen_fd = -1, accept_fd = -1, client_fd = -1;
	struct nstoken *nstoken;
	static char buf[5000];
	int n, ret = -1;

	nstoken = open_netns(NS_3);
	if (!ASSERT_OK_PTR(nstoken, "setns"))
		return -1;

	listen_fd = start_server(family, SOCK_STREAM, dst, 9000, 0);
	if (!ASSERT_GE(listen_fd, 0, "listen"))
		goto done;

	close_netns(nstoken);
	nstoken = open_netns(NS_1);
	if (!ASSERT_OK_PTR(nstoken, "setns src"))
		goto done;

	client_fd = connect_to_fd(listen_fd, TIMEOUT_MILLIS);
	if (!ASSERT_GE(client_fd, 0, "connect_to_fd"))
		goto done;

	accept_fd = accept(listen_fd, NULL, NULL);
	if (!ASSERT_GE(accept_fd, 0, "accept"))
		goto done;

	if (!ASSERT_OK(settimeo(accept_fd, TIMEOUT_MILLIS), "settimeo"))
		goto done;

	/* Send a packet larger than the MTU */
	n = write(client_fd, buf, sizeof(buf));
	if (!ASSERT_EQ(n, sizeof(buf), "send to server"))
		goto done;

	sleep(2); /* let the packet get delivered */

	n = read(accept_fd, buf, sizeof(buf));
	ASSERT_EQ(n, sizeof(buf), "recv from server");

	ret = 0;

done:
	if (nstoken)
		close_netns(nstoken);
	if (listen_fd >= 0)
		close(listen_fd);
	if (accept_fd >= 0)
		close(accept_fd);
	if (client_fd >= 0)
		close(client_fd);
	return ret;
}

static void lwt_ip_encap_test(int encap_family, enum encap_type encap_type)
{
	const char *prog_sec, *encap_dev, *lwt_type, *encap_ns;
	bool bindtodev = true;

	if (!ASSERT_OK(setup_namespaces("add"), "setup namespaces"))
		return;
	if (!ASSERT_OK(setup_links_and_routes(),
		       "setup links and routes"))
		goto fail;

	sleep(2); /* reduce flakiness */

	/* by default, pings work */
	test_ping(AF_INET, false, bindtodev);
	test_ping(AF_INET6, false, bindtodev);

	/* remove NS2->DST routes, ping fails */
	SET_NS_ADDR_ROUTE("del", NS_2, IP4_DST, "dev veth3");
	SET_NS_ADDR_ROUTE("del", NS_2, IP6_DST, "dev veth3");

	test_ping(AF_INET, true, bindtodev);
	test_ping(AF_INET6, true, bindtodev);

	prog_sec = encap_family == AF_INET ? "encap_gre" : "encap_gre6";

	switch (encap_type) {
	case ENCAP_EGRESS:
		encap_dev = "veth1";
		lwt_type = "xmit";
		encap_ns = NS_1;
		break;
	case ENCAP_INGRESS:
		encap_dev = "veth2";
		lwt_type = "in";
		encap_ns = NS_2;
		break;
	case ENCAP_EGRESS_MD:
		switch (encap_family) {
		case AF_INET:
			prog_sec = "encap_gre_md";
			encap_dev = "gre_md";
			break;
		case AF_INET6:
			prog_sec = "encap_gre6_md";
			encap_dev = "gre6_md";
			break;
		default:
			goto fail;
		}
		lwt_type = "xmit";
		encap_ns = NS_1;
		break;
	default:
		goto fail;
	}

	/* install replacement routes (LWT/eBPF), pings succeed */
	SET_NS_ADDR_ROUTE("add", encap_ns, IP4_DST,
			  "encap bpf %s obj test_lwt_ip_encap.o sec %s dev %s",
			  lwt_type, prog_sec, encap_dev);
	SET_NS_ADDR_ROUTE("add", encap_ns, IP6_DST,
			  "encap bpf %s obj test_lwt_ip_encap.o sec %s dev %s",
			  lwt_type, prog_sec, encap_dev);

	/* binding to device doesn't work for egress_md tests as routing is
	 * asymmetrical
	 */
	bindtodev = encap_type != ENCAP_EGRESS_MD;
	test_ping(AF_INET, false, bindtodev);
	test_ping(AF_INET6, false, bindtodev);

	/* VRF is complex for testing GSO in this setup */
	if (!use_vrf && encap_type != ENCAP_INGRESS) {
		test_gso(AF_INET, IP4_DST);
		test_gso(AF_INET6, IP6_DST);
	}

	/* a negative test: remove routes to GRE devices: ping fails */
	if (remove_routes_to_gredev())
		goto fail;

	test_ping(AF_INET, true, bindtodev);
	test_ping(AF_INET6, true, bindtodev);

	if (add_unreachable_routes_to_gredev())
		goto fail;

	test_ping(AF_INET, true, bindtodev);
	test_ping(AF_INET6, true, bindtodev);
fail:
	setup_namespaces("delete");
}

#define RUN_TEST(name, family, encap_type, _use_vrf)		\
	({							\
		if (test__start_subtest(name)) {		\
			use_vrf = _use_vrf;			\
			lwt_ip_encap_test(family, encap_type);	\
		}						\
	})

static void *lwt_ip_encap_run_tests(void *arg)
{
	setup_namespaces_nofail("delete");

	RUN_TEST("lwt_ipv4_encap_egress", AF_INET, ENCAP_EGRESS, false);
	RUN_TEST("lwt_ipv6_encap_egress", AF_INET6, ENCAP_EGRESS, false);
	RUN_TEST("lwt_ipv4_encap_egress_vrf", AF_INET, ENCAP_EGRESS, true);
	RUN_TEST("lwt_ipv6_encap_egress_vrf", AF_INET6, ENCAP_EGRESS, true);

	RUN_TEST("lwt_ipv4_encap_ingress", AF_INET, ENCAP_INGRESS, false);
	RUN_TEST("lwt_ipv6_encap_ingress", AF_INET6, ENCAP_INGRESS, false);
	RUN_TEST("lwt_ipv4_encap_ingress_vrf", AF_INET, ENCAP_INGRESS, true);
	RUN_TEST("lwt_ipv6_encap_ingress_vrf", AF_INET6, ENCAP_INGRESS, true);

	/* bpf_set_tunnel_key() doesn't support setting underlying VRF routing
	 * so egress_md tests don't run in VRF setup.
	 */
	RUN_TEST("lwt_ipv4_encap_egress_md", AF_INET, ENCAP_EGRESS_MD, false);
	RUN_TEST("lwt_ipv6_encap_egress_md", AF_INET6, ENCAP_EGRESS_MD, false);
	return NULL;
}

void serial_test_lwt_ip_encap(void)
{
	pthread_t test_thread;
	int err;

	/* Run the tests in their own thread to isolate the namespace changes
	 * so they do not affect the environment of other tests.
	 * (specifically needed because of unshare(CLONE_NEWNS) in open_netns())
	 */
	err = pthread_create(&test_thread, NULL, &lwt_ip_encap_run_tests, NULL);
	if (ASSERT_OK(err, "pthread_create"))
		ASSERT_OK(pthread_join(test_thread, NULL), "pthread_join");
}
