// SPDX-License-Identifier: GPL-2.0

/**
 * Test XDP bonding support
 *
 * Sets up two bonded veth pairs between two fresh namespaces
 * and verifies that XDP_TX program loaded on a bond device
 * are correctly loaded onto the slave devices and XDP_TX'd
 * packets are balanced using bonding.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <net/if.h>
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/if_bonding.h>
#include <linux/limits.h>
#include <linux/if_ether.h>
#include <linux/udp.h>

#define BOND1_MAC {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
#define BOND1_MAC_STR "00:11:22:33:44:55"
#define BOND2_MAC {0x00, 0x22, 0x33, 0x44, 0x55, 0x66}
#define BOND2_MAC_STR "00:22:33:44:55:66"
#define NPACKETS 100

static int root_netns_fd = -1;

static void restore_root_netns(void)
{
	ASSERT_OK(setns(root_netns_fd, CLONE_NEWNET), "restore_root_netns");
}

int setns_by_name(char *name)
{
	int nsfd, err;
	char nspath[PATH_MAX];

	snprintf(nspath, sizeof(nspath), "%s/%s", "/var/run/netns", name);
	nsfd = open(nspath, O_RDONLY | O_CLOEXEC);
	if (nsfd < 0)
		return -1;

	err = setns(nsfd, CLONE_NEWNET);
	close(nsfd);
	return err;
}

static int get_rx_packets(const char *iface)
{
	FILE *f;
	char line[512];
	int iface_len = strlen(iface);

	f = fopen("/proc/net/dev", "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		char *p = line;

		while (*p == ' ')
			p++; /* skip whitespace */
		if (!strncmp(p, iface, iface_len)) {
			p += iface_len;
			if (*p++ != ':')
				continue;
			while (*p == ' ')
				p++; /* skip whitespace */
			while (*p && *p != ' ')
				p++; /* skip rx bytes */
			while (*p == ' ')
				p++; /* skip whitespace */
			fclose(f);
			return atoi(p);
		}
	}
	fclose(f);
	return -1;
}

enum {
	BOND_ONE_NO_ATTACH = 0,
	BOND_BOTH_AND_ATTACH,
};

static int bonding_setup(int mode, int xmit_policy, int bond_both_attach)
{
#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			return -1;				\
	})

	SYS("ip netns add ns_dst");
	SYS("ip link add veth1_1 type veth peer name veth2_1 netns ns_dst");
	SYS("ip link add veth1_2 type veth peer name veth2_2 netns ns_dst");

	SYS("modprobe -r bonding &> /dev/null");
	SYS("modprobe bonding mode=%d packets_per_slave=1 xmit_hash_policy=%d", mode, xmit_policy);

	SYS("ip link add bond1 type bond");
	SYS("ip link set bond1 address " BOND1_MAC_STR);
	SYS("ip link set bond1 up");
	SYS("ip -netns ns_dst link add bond2 type bond");
	SYS("ip -netns ns_dst link set bond2 address " BOND2_MAC_STR);
	SYS("ip -netns ns_dst link set bond2 up");

	SYS("ip link set veth1_1 master bond1");
	if (bond_both_attach == BOND_BOTH_AND_ATTACH) {
		SYS("ip link set veth1_2 master bond1");
	} else {
		SYS("ip link set veth1_2 up");
		SYS("ip link set dev veth1_2 xdpdrv obj xdp_dummy.o sec xdp_dummy");
	}

	SYS("ip -netns ns_dst link set veth2_1 master bond2");

	if (bond_both_attach == BOND_BOTH_AND_ATTACH)
		SYS("ip -netns ns_dst link set veth2_2 master bond2");
	else
		SYS("ip -netns ns_dst link set veth2_2 up");

	/* Load a dummy program on sending side as with veth peer needs to have a
	 * XDP program loaded as well.
	 */
	SYS("ip link set dev bond1 xdpdrv obj xdp_dummy.o sec xdp_dummy");

	if (bond_both_attach == BOND_BOTH_AND_ATTACH)
		SYS("ip -netns ns_dst link set dev bond2 xdpdrv obj xdp_tx.o sec tx");

#undef SYS
	return 0;
}

static void bonding_cleanup(void)
{
	ASSERT_OK(system("ip link delete veth1_1"), "delete veth1_1");
	ASSERT_OK(system("ip link delete veth1_2"), "delete veth1_2");
	ASSERT_OK(system("ip netns delete ns_dst"), "delete ns_dst");
	ASSERT_OK(system("modprobe -r bonding"), "unload bond");
}

static int send_udp_packets(int vary_dst_ip)
{
	int i, s = -1;
	int ifindex;
	uint8_t buf[128] = {};
	struct ethhdr eh = {
		.h_source = BOND1_MAC,
		.h_dest = BOND2_MAC,
		.h_proto = htons(ETH_P_IP),
	};
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(eh));
	struct udphdr *uh = (struct udphdr *)(buf + sizeof(eh) + sizeof(*iph));

	s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (!ASSERT_GE(s, 0, "socket"))
		goto err;

	ifindex = if_nametoindex("bond1");
	if (!ASSERT_GT(ifindex, 0, "get bond1 ifindex"))
		goto err;

	memcpy(buf, &eh, sizeof(eh));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16;
	iph->id = 1;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = 1;
	iph->daddr = 2;
	iph->tot_len = htons(sizeof(buf) - ETH_HLEN);
	iph->check = 0;

	for (i = 1; i <= NPACKETS; i++) {
		int n;
		struct sockaddr_ll saddr_ll = {
			.sll_ifindex = ifindex,
			.sll_halen = ETH_ALEN,
			.sll_addr = BOND2_MAC,
		};

		/* vary the UDP destination port for even distribution with roundrobin/xor modes */
		uh->dest++;

		if (vary_dst_ip)
			iph->daddr++;

		n = sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&saddr_ll, sizeof(saddr_ll));
		if (!ASSERT_EQ(n, sizeof(buf), "sendto"))
			goto err;
	}

	return 0;

err:
	if (s >= 0)
		close(s);
	return -1;
}

void test_xdp_bonding_with_mode(char *name, int mode, int xmit_policy)
{
	int bond1_rx;

	if (!test__start_subtest(name))
		return;

	if (bonding_setup(mode, xmit_policy, BOND_BOTH_AND_ATTACH))
		return;

	if (send_udp_packets(xmit_policy != BOND_XMIT_POLICY_LAYER34))
		return;

	bond1_rx = get_rx_packets("bond1");
	ASSERT_TRUE(
		bond1_rx >= NPACKETS,
		"expected more received packets");

	switch (mode) {
	case BOND_MODE_ROUNDROBIN:
	case BOND_MODE_XOR: {
		int veth1_rx = get_rx_packets("veth1_1");
		int veth2_rx = get_rx_packets("veth1_2");
		int diff = abs(veth1_rx - veth2_rx);

		ASSERT_GE(veth1_rx + veth2_rx, NPACKETS, "expected more packets");

		switch (xmit_policy) {
		case BOND_XMIT_POLICY_LAYER2:
			ASSERT_GE(diff, NPACKETS/2,
				  "expected packets on only one of the interfaces");
			break;
		case BOND_XMIT_POLICY_LAYER23:
		case BOND_XMIT_POLICY_LAYER34:
			ASSERT_LT(diff, NPACKETS/2,
				  "expected even distribution of packets");
			break;
		default:
			abort();
		}
		break;
	}
	default:
		break;
	}

	bonding_cleanup();
}

void test_xdp_bonding_redirect_multi(void)
{
	static const char * const ifaces[] = {"bond2", "veth2_1", "veth2_2"};
	int veth1_rx, veth2_rx;
	int err;

	if (!test__start_subtest("xdp_bonding_redirect_multi"))
		return;

	if (bonding_setup(BOND_MODE_ROUNDROBIN, BOND_XMIT_POLICY_LAYER23, BOND_ONE_NO_ATTACH))
		goto out;

	err = system("ip -netns ns_dst link set dev bond2 xdpdrv "
		     "obj xdp_redirect_multi_kern.o sec xdp_redirect_map_multi");
	if (!ASSERT_OK(err, "link set xdpdrv"))
		goto out;

	/* populate the redirection devmap with the relevant interfaces */
	if (!ASSERT_OK(setns_by_name("ns_dst"), "could not set netns to ns_dst"))
		goto out;

	for (int i = 0; i < ARRAY_SIZE(ifaces); i++) {
		char cmd[512];
		int ifindex = if_nametoindex(ifaces[i]);

		if (!ASSERT_GT(ifindex, 0, "could not get interface index"))
			goto out;

		snprintf(cmd, sizeof(cmd),
			 "ip netns exec ns_dst bpftool map update name map_all key %d 0 0 0 value %d 0 0 0",
			 i, ifindex);

		if (!ASSERT_OK(system(cmd), "bpftool map update"))
			goto out;
	}
	restore_root_netns();

	send_udp_packets(BOND_MODE_ROUNDROBIN);

	veth1_rx = get_rx_packets("veth1_1");
	veth2_rx = get_rx_packets("veth1_2");

	ASSERT_LT(veth1_rx, NPACKETS/2, "expected few packets on veth1");
	ASSERT_GE(veth2_rx, NPACKETS, "expected more packets on veth2");
out:
	restore_root_netns();
	bonding_cleanup();
}

struct bond_test_case {
	char *name;
	int mode;
	int xmit_policy;
};

static	struct bond_test_case bond_test_cases[] = {
	{ "xdp_bonding_roundrobin", BOND_MODE_ROUNDROBIN, BOND_XMIT_POLICY_LAYER23, },
	{ "xdp_bonding_activebackup", BOND_MODE_ACTIVEBACKUP, BOND_XMIT_POLICY_LAYER23 },

	{ "xdp_bonding_xor_layer2", BOND_MODE_XOR, BOND_XMIT_POLICY_LAYER2, },
	{ "xdp_bonding_xor_layer23", BOND_MODE_XOR, BOND_XMIT_POLICY_LAYER23, },
	{ "xdp_bonding_xor_layer34", BOND_MODE_XOR, BOND_XMIT_POLICY_LAYER34, },
};

void test_xdp_bonding(void)
{
	int i;

	root_netns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (!ASSERT_GE(root_netns_fd, 0, "open /proc/self/ns/net"))
		return;

	for (i = 0; i < ARRAY_SIZE(bond_test_cases); i++) {
		struct bond_test_case *test_case = &bond_test_cases[i];

		test_xdp_bonding_with_mode(
			test_case->name,
			test_case->mode,
			test_case->xmit_policy);
	}

	test_xdp_bonding_redirect_multi();
}
