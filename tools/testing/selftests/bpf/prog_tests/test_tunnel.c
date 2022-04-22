// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * End-to-end eBPF tunnel test suite
 *   The file tests BPF network tunnel implementation.
 *
 * Topology:
 * ---------
 *     root namespace   |     at_ns0 namespace
 *                       |
 *       -----------     |     -----------
 *       | tnl dev |     |     | tnl dev |  (overlay network)
 *       -----------     |     -----------
 *       metadata-mode   |     native-mode
 *        with bpf       |
 *                       |
 *       ----------      |     ----------
 *       |  veth1  | --------- |  veth0  |  (underlay network)
 *       ----------    peer    ----------
 *
 *
 *  Device Configuration
 *  --------------------
 *  root namespace with metadata-mode tunnel + BPF
 *  Device names and addresses:
 *	veth1 IP 1: 172.16.1.200, IPv6: 00::22 (underlay)
 *		IP 2: 172.16.1.20, IPv6: 00::bb (underlay)
 *	tunnel dev <type>11, ex: gre11, IPv4: 10.1.1.200, IPv6: 1::22 (overlay)
 *
 *  Namespace at_ns0 with native tunnel
 *  Device names and addresses:
 *	veth0 IPv4: 172.16.1.100, IPv6: 00::11 (underlay)
 *	tunnel dev <type>00, ex: gre00, IPv4: 10.1.1.100, IPv6: 1::11 (overlay)
 *
 *
 * End-to-end ping packet flow
 *  ---------------------------
 *  Most of the tests start by namespace creation, device configuration,
 *  then ping the underlay and overlay network.  When doing 'ping 10.1.1.100'
 *  from root namespace, the following operations happen:
 *  1) Route lookup shows 10.1.1.100/24 belongs to tnl dev, fwd to tnl dev.
 *  2) Tnl device's egress BPF program is triggered and set the tunnel metadata,
 *     with local_ip=172.16.1.200, remote_ip=172.16.1.100. BPF program choose
 *     the primary or secondary ip of veth1 as the local ip of tunnel. The
 *     choice is made based on the value of bpf map local_ip_map.
 *  3) Outer tunnel header is prepended and route the packet to veth1's egress.
 *  4) veth0's ingress queue receive the tunneled packet at namespace at_ns0.
 *  5) Tunnel protocol handler, ex: vxlan_rcv, decap the packet.
 *  6) Forward the packet to the overlay tnl dev.
 */

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/limits.h>
#include <linux/sysctl.h>
#include <linux/time_types.h>
#include <linux/net_tstamp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "test_tunnel_kern.skel.h"

#define IP4_ADDR_VETH0 "172.16.1.100"
#define IP4_ADDR1_VETH1 "172.16.1.200"
#define IP4_ADDR2_VETH1 "172.16.1.20"
#define IP4_ADDR_TUNL_DEV0 "10.1.1.100"
#define IP4_ADDR_TUNL_DEV1 "10.1.1.200"

#define IP6_ADDR_VETH0 "::11"
#define IP6_ADDR1_VETH1 "::22"
#define IP6_ADDR2_VETH1 "::bb"

#define IP4_ADDR1_HEX_VETH1 0xac1001c8
#define IP4_ADDR2_HEX_VETH1 0xac100114
#define IP6_ADDR1_HEX_VETH1 0x22
#define IP6_ADDR2_HEX_VETH1 0xbb

#define MAC_TUNL_DEV0 "52:54:00:d9:01:00"
#define MAC_TUNL_DEV1 "52:54:00:d9:02:00"

#define VXLAN_TUNL_DEV0 "vxlan00"
#define VXLAN_TUNL_DEV1 "vxlan11"
#define IP6VXLAN_TUNL_DEV0 "ip6vxlan00"
#define IP6VXLAN_TUNL_DEV1 "ip6vxlan11"

#define SRC_INGRESS_PROG_PIN_FILE "/sys/fs/bpf/tc/test_tunnel_ingress_src"
#define SRC_EGRESS_PROG_PIN_FILE "/sys/fs/bpf/tc/test_tunnel_egress_src"
#define DST_EGRESS_PROG_PIN_FILE "/sys/fs/bpf/tc/test_tunnel_egress_dst"

#define PING_ARGS "-c 3 -w 10 -q"

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

static int config_device(void)
{
	SYS("ip netns add at_ns0");
	SYS("ip link add veth0 type veth peer name veth1");
	SYS("ip link set veth0 netns at_ns0");
	SYS("ip addr add " IP4_ADDR1_VETH1 "/24 dev veth1");
	SYS("ip link set dev veth1 up mtu 1500");
	SYS("ip netns exec at_ns0 ip addr add " IP4_ADDR_VETH0 "/24 dev veth0");
	SYS("ip netns exec at_ns0 ip link set dev veth0 up mtu 1500");

	return 0;
fail:
	return -1;
}

static void cleanup(void)
{
	SYS_NOFAIL("test -f /var/run/netns/at_ns0 && ip netns delete at_ns0");
	SYS_NOFAIL("ip link del veth1 2> /dev/null");
	SYS_NOFAIL("ip link del %s 2> /dev/null", VXLAN_TUNL_DEV1);
	SYS_NOFAIL("ip link del %s 2> /dev/null", IP6VXLAN_TUNL_DEV1);

	SYS_NOFAIL("rm -rf %s", SRC_INGRESS_PROG_PIN_FILE);
	SYS_NOFAIL("rm -rf %s", SRC_EGRESS_PROG_PIN_FILE);
}

static int add_vxlan_tunnel(void)
{
	/* at_ns0 namespace */
	SYS("ip netns exec at_ns0 ip link add dev %s type vxlan external gbp dstport 4789",
	    VXLAN_TUNL_DEV0);
	SYS("ip netns exec at_ns0 ip link set dev %s address %s up",
	    VXLAN_TUNL_DEV0, MAC_TUNL_DEV0);
	SYS("ip netns exec at_ns0 ip addr add dev %s %s/24",
	    VXLAN_TUNL_DEV0, IP4_ADDR_TUNL_DEV0);
	SYS("ip netns exec at_ns0 ip neigh add %s lladdr %s dev %s",
	    IP4_ADDR_TUNL_DEV1, MAC_TUNL_DEV1, VXLAN_TUNL_DEV0);

	/* root namespace */
	SYS("ip link add dev %s type vxlan external gbp dstport 4789",
	    VXLAN_TUNL_DEV1);
	SYS("ip link set dev %s address %s up", VXLAN_TUNL_DEV1, MAC_TUNL_DEV1);
	SYS("ip addr add dev %s %s/24", VXLAN_TUNL_DEV1, IP4_ADDR_TUNL_DEV1);
	SYS("ip neigh add %s lladdr %s dev %s",
	    IP4_ADDR_TUNL_DEV0, MAC_TUNL_DEV0, VXLAN_TUNL_DEV1);

	return 0;
fail:
	return -1;
}

static int add_ip6vxlan_tunnel(void)
{
	SYS("ip netns exec at_ns0 ip -6 addr add %s/96 dev veth0",
	    IP6_ADDR_VETH0);
	SYS("ip netns exec at_ns0 ip link set dev veth0 up");
	SYS("ip -6 addr add %s/96 dev veth1", IP6_ADDR1_VETH1);
	SYS("ip link set dev veth1 up");

	/* at_ns0 namespace */
	SYS("ip netns exec at_ns0 ip link add dev %s type vxlan external dstport 4789",
	    IP6VXLAN_TUNL_DEV0);
	SYS("ip netns exec at_ns0 ip addr add dev %s %s/24",
	    IP6VXLAN_TUNL_DEV0, IP4_ADDR_TUNL_DEV0);
	SYS("ip netns exec at_ns0 ip link set dev %s address %s up",
	    IP6VXLAN_TUNL_DEV0, MAC_TUNL_DEV0);

	/* root namespace */
	SYS("ip link add dev %s type vxlan external dstport 4789",
	    IP6VXLAN_TUNL_DEV1);
	SYS("ip addr add dev %s %s/24", IP6VXLAN_TUNL_DEV1, IP4_ADDR_TUNL_DEV1);
	SYS("ip link set dev %s address %s up",
	    IP6VXLAN_TUNL_DEV1, MAC_TUNL_DEV1);

	return 0;
fail:
	return -1;
}

static int test_ping4(void)
{
	/* underlay */
	SYS("ping " PING_ARGS " %s > /dev/null", IP4_ADDR_VETH0);
	/* overlay, ping root -> at_ns0 */
	SYS("ping " PING_ARGS " %s > /dev/null", IP4_ADDR_TUNL_DEV0);

	/* overlay, ping at_ns0 -> root */
	SYS("ip netns exec at_ns0 ping " PING_ARGS " %s > /dev/null",
	    IP4_ADDR_TUNL_DEV1);
	return 0;
fail:
	return -1;
}

static void test_vxlan_tunnel(void)
{
	struct test_tunnel_kern *skel = NULL;
	struct nstoken *nstoken;
	int local_ip_map_fd = 0, key = 0;
	uint local_ip;
	int err;

	/* add vxlan tunnel */
	err = add_vxlan_tunnel();
	if (!ASSERT_OK(err, "add vxlan tunnel"))
		goto done;

	/* load and attach bpf prog to tunnel dev tc hook point */
	skel = test_tunnel_kern__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_tunnel_kern__open_and_load"))
		goto done;
	err = bpf_program__pin(skel->progs.vxlan_set_tunnel_src,
			       SRC_EGRESS_PROG_PIN_FILE);
	if (!ASSERT_OK(err, "pin " SRC_EGRESS_PROG_PIN_FILE))
		goto done;
	err = bpf_program__pin(skel->progs.vxlan_get_tunnel_src,
			       SRC_INGRESS_PROG_PIN_FILE);
	if (!ASSERT_OK(err, "pin " SRC_INGRESS_PROG_PIN_FILE))
		goto done;
	SYS("tc qdisc add dev %s clsact", VXLAN_TUNL_DEV1);
	SYS("tc filter add dev %s ingress bpf da object-pinned %s",
	    VXLAN_TUNL_DEV1, SRC_INGRESS_PROG_PIN_FILE);
	SYS("tc filter add dev %s egress bpf da object-pinned %s",
	    VXLAN_TUNL_DEV1, SRC_EGRESS_PROG_PIN_FILE);

	local_ip_map_fd = bpf_map__fd(skel->maps.local_ip_map);
	if (!ASSERT_GE(local_ip_map_fd, 0, "get local_ip_map fd "))
		goto done;

	/* load and attach prog set_md to tunnel dev tc hook point at_ns0 */
	nstoken = open_netns("at_ns0");
	if (!ASSERT_OK_PTR(nstoken, "setns src"))
		goto fail;
	err = bpf_program__pin(skel->progs.vxlan_set_tunnel_dst,
			       DST_EGRESS_PROG_PIN_FILE);
	if (!ASSERT_OK(err, "pin " DST_EGRESS_PROG_PIN_FILE))
		goto done;
	SYS("tc qdisc add dev %s clsact", VXLAN_TUNL_DEV0);
	SYS("tc filter add dev %s egress bpf da object-pinned %s",
	    VXLAN_TUNL_DEV0, DST_EGRESS_PROG_PIN_FILE);
	close_netns(nstoken);

	/* use veth1 ip 1 as tunnel source ip */
	local_ip = IP4_ADDR1_HEX_VETH1;
	err = bpf_map_update_elem(local_ip_map_fd, &key, &local_ip, BPF_ANY);
	if (!ASSERT_OK(err, "update bpf local_ip_map"))
		goto done;

	/* ping test */
	err = test_ping4();
	if (!ASSERT_OK(err, "test ping ipv4"))
		goto done;

	/* use veth1 ip 2 as tunnel source ip */
	SYS("ip addr add " IP4_ADDR2_VETH1 "/24 dev veth1");
	local_ip = IP4_ADDR2_HEX_VETH1;
	err = bpf_map_update_elem(local_ip_map_fd, &key, &local_ip, BPF_ANY);
	if (!ASSERT_OK(err, "update bpf local_ip_map"))
		goto done;

	/* ping test */
	err = test_ping4();
	if (!ASSERT_OK(err, "test ping ipv4"))
		goto done;

fail:
done:
	if (local_ip_map_fd >= 0)
		close(local_ip_map_fd);
	if (skel)
		test_tunnel_kern__destroy(skel);
}

static void test_ip6vxlan_tunnel(void)
{
	struct test_tunnel_kern *skel = NULL;
	struct nstoken *nstoken;
	int local_ip_map_fd = 0, key = 0;
	uint local_ip;
	int err;

	/* add vxlan tunnel */
	err = add_ip6vxlan_tunnel();
	if (!ASSERT_OK(err, "add ip6vxlan tunnel"))
		goto done;

	/* load and attach bpf prog to tunnel dev tc hook point */
	skel = test_tunnel_kern__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_tunnel_kern__open_and_load"))
		goto done;
	err = bpf_program__pin(skel->progs.ip6vxlan_set_tunnel_src,
			       SRC_EGRESS_PROG_PIN_FILE);
	if (!ASSERT_OK(err, "pin " SRC_EGRESS_PROG_PIN_FILE))
		goto done;
	err = bpf_program__pin(skel->progs.ip6vxlan_get_tunnel_src,
			       SRC_INGRESS_PROG_PIN_FILE);
	if (!ASSERT_OK(err, "pin " SRC_INGRESS_PROG_PIN_FILE))
		goto done;
	SYS("tc qdisc add dev %s clsact", IP6VXLAN_TUNL_DEV1);
	SYS("tc filter add dev %s ingress bpf da object-pinned %s",
	    IP6VXLAN_TUNL_DEV1, SRC_INGRESS_PROG_PIN_FILE);
	SYS("tc filter add dev %s egress bpf da object-pinned %s",
	    IP6VXLAN_TUNL_DEV1, SRC_EGRESS_PROG_PIN_FILE);

	local_ip_map_fd = bpf_map__fd(skel->maps.local_ip_map);
	if (!ASSERT_GE(local_ip_map_fd, 0, "get local_ip_map fd "))
		goto done;

	/* load and attach prog set_md to tunnel dev tc hook point at_ns0 */
	nstoken = open_netns("at_ns0");
	if (!ASSERT_OK_PTR(nstoken, "setns src"))
		goto fail;
	err = bpf_program__pin(skel->progs.ip6vxlan_set_tunnel_dst,
			       DST_EGRESS_PROG_PIN_FILE);
	if (!ASSERT_OK(err, "pin " DST_EGRESS_PROG_PIN_FILE))
		goto done;
	SYS("tc qdisc add dev %s clsact", IP6VXLAN_TUNL_DEV0);
	SYS("tc filter add dev %s egress bpf da object-pinned %s",
	    IP6VXLAN_TUNL_DEV0, DST_EGRESS_PROG_PIN_FILE);
	close_netns(nstoken);

	/* use veth1 ip 1 as tunnel source ip */
	local_ip = IP6_ADDR1_HEX_VETH1;
	err = bpf_map_update_elem(local_ip_map_fd, &key, &local_ip, BPF_ANY);
	if (!ASSERT_OK(err, "update bpf local_ip_map"))
		goto done;

	/* ping test */
	err = test_ping4();
	if (!ASSERT_OK(err, "test ping ipv4"))
		goto done;

	/* use veth1 ip 2 as tunnel source ip */
	SYS("ip -6 addr add " IP6_ADDR2_VETH1 "/96 dev veth1");
	local_ip = IP6_ADDR2_HEX_VETH1;
	err = bpf_map_update_elem(local_ip_map_fd, &key, &local_ip, BPF_ANY);
	if (!ASSERT_OK(err, "update bpf local_ip_map"))
		goto done;

	/* ping test */
	err = test_ping4();
	if (!ASSERT_OK(err, "test ping ipv4"))
		goto done;

fail:
done:
	if (local_ip_map_fd >= 0)
		close(local_ip_map_fd);
	if (skel)
		test_tunnel_kern__destroy(skel);
}

#define RUN_TEST(name)							\
	({								\
		if (test__start_subtest(#name)) {			\
			if (ASSERT_OK(config_device(), "config device"))\
				test_ ## name();			\
			cleanup();					\
		}							\
	})

static void *test_tunnel_run_tests(void *arg)
{
	cleanup();

	RUN_TEST(vxlan_tunnel);
	RUN_TEST(ip6vxlan_tunnel);

	return NULL;
}

void serial_test_tunnel(void)
{
	pthread_t test_thread;
	int err;

	/* Run the tests in their own thread to isolate the namespace changes
	 * so they do not affect the environment of other tests.
	 * (specifically needed because of unshare(CLONE_NEWNS) in open_netns())
	 */
	err = pthread_create(&test_thread, NULL, &test_tunnel_run_tests, NULL);
	if (ASSERT_OK(err, "pthread_create"))
		ASSERT_OK(pthread_join(test_thread, NULL), "pthread_join");
}
