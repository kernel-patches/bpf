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
#include <net/if.h>
#include <linux/if_link.h>
#include "test_progs.h"
#include "network_helpers.h"
#include <linux/if_bonding.h>
#include <linux/limits.h>
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

static const char * const mode_names[] = {
	[BOND_MODE_ROUNDROBIN]   = "balance-rr",
	[BOND_MODE_ACTIVEBACKUP] = "active-backup",
	[BOND_MODE_XOR]          = "balance-xor",
	[BOND_MODE_BROADCAST]    = "broadcast",
	[BOND_MODE_8023AD]       = "802.3ad",
	[BOND_MODE_TLB]          = "balance-tlb",
	[BOND_MODE_ALB]          = "balance-alb",
};

static const char * const xmit_policy_names[] = {
	[BOND_XMIT_POLICY_LAYER2]       = "layer2",
	[BOND_XMIT_POLICY_LAYER34]      = "layer3+4",
	[BOND_XMIT_POLICY_LAYER23]      = "layer2+3",
	[BOND_XMIT_POLICY_ENCAP23]      = "encap2+3",
	[BOND_XMIT_POLICY_ENCAP34]      = "encap3+4",
};

#define MAX_LOADED 8
static struct bpf_object *loaded_bpf_objects[MAX_LOADED] = {};
static int n_loaded_bpf_objects;

static int load_xdp_program(const char *filename, const char *sec_name, const char *iface)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = filename,
	};
	struct bpf_program *prog;
	struct bpf_object *obj;
	int prog_fd = -1;
	int ifindex, err;

	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
	if (!ASSERT_OK(err, "prog load xattr"))
		return err;

	prog = bpf_object__find_program_by_title(obj, sec_name);
	if (!ASSERT_OK_PTR(prog, "find program"))
		goto err;

	prog_fd = bpf_program__fd(prog);
	if (!ASSERT_GE(prog_fd, 0, "get program fd"))
		goto err;

	ifindex = if_nametoindex(iface);
	if (!ASSERT_GT(ifindex, 0, "get ifindex"))
		goto err;

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE | XDP_FLAGS_DRV_MODE);
	if (!ASSERT_OK(err, "load xdp program"))
		goto err;

	loaded_bpf_objects[n_loaded_bpf_objects++] = obj;
	if (n_loaded_bpf_objects == MAX_LOADED) {
		fprintf(stderr, "Too many loaded BPF objects\n");
		goto err;
	}

	return 0;

err:
	bpf_object__close(obj);
	return -1;
}

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

	SYS("ip link add bond1 type bond mode %s xmit_hash_policy %s",
	    mode_names[mode], xmit_policy_names[xmit_policy]);
	SYS("ip link set bond1 up address " BOND1_MAC_STR " addrgenmode none");
	SYS("ip -netns ns_dst link add bond2 type bond mode %s xmit_hash_policy %s",
	    mode_names[mode], xmit_policy_names[xmit_policy]);
	SYS("ip -netns ns_dst link set bond2 up address " BOND2_MAC_STR " addrgenmode none");

	SYS("ip link set veth1_1 master bond1");
	if (bond_both_attach == BOND_BOTH_AND_ATTACH) {
		SYS("ip link set veth1_2 master bond1");
	} else {
		SYS("ip link set veth1_2 up addrgenmode none");

		if (load_xdp_program("xdp_dummy.o", "xdp_dummy", "veth1_2"))
			return -1;
	}

	SYS("ip -netns ns_dst link set veth2_1 master bond2");

	if (bond_both_attach == BOND_BOTH_AND_ATTACH)
		SYS("ip -netns ns_dst link set veth2_2 master bond2");
	else
		SYS("ip -netns ns_dst link set veth2_2 up addrgenmode none");

	/* Load a dummy program on sending side as with veth peer needs to have a
	 * XDP program loaded as well.
	 */
	if (load_xdp_program("xdp_dummy.o", "xdp_dummy", "bond1"))
		return -1;

	if (bond_both_attach == BOND_BOTH_AND_ATTACH) {
		if (!ASSERT_OK(setns_by_name("ns_dst"), "set netns to ns_dst"))
			return -1;
		if (load_xdp_program("xdp_tx.o", "tx", "bond2"))
			return -1;
		restore_root_netns();
	}

#undef SYS
	return 0;
}

static void bonding_cleanup(void)
{
	restore_root_netns();
	while (n_loaded_bpf_objects) {
		n_loaded_bpf_objects--;
		bpf_object__close(loaded_bpf_objects[n_loaded_bpf_objects]);
	}
	ASSERT_OK(system("ip link delete bond1"), "delete bond1");
	ASSERT_OK(system("ip link delete veth1_1"), "delete veth1_1");
	ASSERT_OK(system("ip link delete veth1_2"), "delete veth1_2");
	ASSERT_OK(system("ip netns delete ns_dst"), "delete ns_dst");
}

static int send_udp_packets(int vary_dst_ip)
{
	struct ethhdr eh = {
		.h_source = BOND1_MAC,
		.h_dest = BOND2_MAC,
		.h_proto = htons(ETH_P_IP),
	};
	uint8_t buf[128] = {};
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(eh));
	struct udphdr *uh = (struct udphdr *)(buf + sizeof(eh) + sizeof(*iph));
	int i, s = -1;
	int ifindex;

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
		goto out;

	if (send_udp_packets(xmit_policy != BOND_XMIT_POLICY_LAYER34))
		goto out;

	bond1_rx = get_rx_packets("bond1");
	ASSERT_EQ(bond1_rx, NPACKETS, "expected more received packets");

	switch (mode) {
	case BOND_MODE_ROUNDROBIN:
	case BOND_MODE_XOR: {
		int veth1_rx = get_rx_packets("veth1_1");
		int veth2_rx = get_rx_packets("veth1_2");
		int diff = abs(veth1_rx - veth2_rx);

		ASSERT_GE(veth1_rx + veth2_rx, NPACKETS, "expected more packets");

		switch (xmit_policy) {
		case BOND_XMIT_POLICY_LAYER2:
			ASSERT_GE(diff, NPACKETS,
				  "expected packets on only one of the interfaces");
			break;
		case BOND_XMIT_POLICY_LAYER23:
		case BOND_XMIT_POLICY_LAYER34:
			ASSERT_LT(diff, NPACKETS/2,
				  "expected even distribution of packets");
			break;
		default:
			PRINT_FAIL("Unimplemented xmit_policy=%d\n", xmit_policy);
			break;
		}
		break;
	}
	case BOND_MODE_ACTIVEBACKUP: {
		int veth1_rx = get_rx_packets("veth1_1");
		int veth2_rx = get_rx_packets("veth1_2");
		int diff = abs(veth1_rx - veth2_rx);

		ASSERT_GE(diff, NPACKETS,
			  "expected packets on only one of the interfaces");
		break;
	}
	default:
		PRINT_FAIL("Unimplemented xmit_policy=%d\n", xmit_policy);
		break;
	}

out:
	bonding_cleanup();
}


/* Test the broadcast redirection using xdp_redirect_map_multi_prog and adding
 * all the interfaces to it and checking that broadcasting won't send the packet
 * to neither the ingress bond device (bond2) or its slave (veth2_1).
 */
void test_xdp_bonding_redirect_multi(void)
{
	static const char * const ifaces[] = {"bond2", "veth2_1", "veth2_2"};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_UNSPEC,
		.file = "xdp_redirect_multi_kern.o",
	};
	struct bpf_program *redirect_prog;
	int prog_fd, map_all_fd;
	struct bpf_object *obj;
	int veth1_1_rx, veth1_2_rx;
	int err;

	if (!test__start_subtest("xdp_bonding_redirect_multi"))
		return;

	if (bonding_setup(BOND_MODE_ROUNDROBIN, BOND_XMIT_POLICY_LAYER23, BOND_ONE_NO_ATTACH))
		goto out;

	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
	if (!ASSERT_OK(err, "prog load xattr"))
		goto out;

	map_all_fd = bpf_object__find_map_fd_by_name(obj, "map_all");
	if (!ASSERT_GE(map_all_fd, 0, "find map_all fd"))
		goto out;

	redirect_prog = bpf_object__find_program_by_name(obj, "xdp_redirect_map_multi_prog");
	if (!ASSERT_OK_PTR(redirect_prog, "find xdp_redirect_map_multi_prog"))
		goto out;

	prog_fd = bpf_program__fd(redirect_prog);
	if (!ASSERT_GE(prog_fd, 0, "get prog fd"))
		goto out;

	if (!ASSERT_OK(setns_by_name("ns_dst"), "could not set netns to ns_dst"))
		goto out;

	/* populate the devmap with the relevant interfaces */
	for (int i = 0; i < ARRAY_SIZE(ifaces); i++) {
		int ifindex = if_nametoindex(ifaces[i]);

		if (!ASSERT_GT(ifindex, 0, "could not get interface index"))
			goto out;

		if (!ASSERT_OK(bpf_map_update_elem(map_all_fd, &ifindex, &ifindex, 0),
			       "add interface to map_all"))
			goto out;
	}

	/* finally attach the program */
	err = bpf_set_link_xdp_fd(if_nametoindex("bond2"), prog_fd,
				  XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
	if (!ASSERT_OK(err, "set bond2 xdp"))
		goto out;

	restore_root_netns();

	if (send_udp_packets(BOND_MODE_ROUNDROBIN))
		goto out;

	veth1_1_rx = get_rx_packets("veth1_1");
	veth1_2_rx = get_rx_packets("veth1_2");

	ASSERT_EQ(veth1_1_rx, 0, "expected no packets on veth1_1");
	ASSERT_GE(veth1_2_rx, NPACKETS, "expected packets on veth1_2");

out:
	restore_root_netns();
	bpf_object__close(obj);
	bonding_cleanup();
}

static int libbpf_debug_print(enum libbpf_print_level level,
			      const char *format, va_list args)
{
	if (level != LIBBPF_WARN)
		vprintf(format, args);
	return 0;
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
	libbpf_print_fn_t old_print_fn;
	int i;

	old_print_fn = libbpf_set_print(libbpf_debug_print);

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

	libbpf_set_print(old_print_fn);
	close(root_netns_fd);
}
