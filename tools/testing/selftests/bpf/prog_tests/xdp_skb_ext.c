// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include "xdp_skb_ext.h"
#include "test_xdp_skb_ext.skel.h"
#include "xdp_skb_ext_success.skel.h"
#include "xdp_skb_ext_failure.skel.h"
#include "xdp_dummy.skel.h"

#define XDP_RSS_TYPE_L3_IPV4 BIT(0)
#define XDP_RSS_TYPE_L4 BIT(3)
#define XDP_RSS_TYPE_L4_IPV4_TCP (BIT(0) | BIT(3) | BIT(4))

#define XDP_CHECKSUM_NONE BIT(0)
#define XDP_CHECKSUM_UNNECESSARY BIT(1)

#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1

#define RX_HASH 0x5a3c91e2
#define RX_VLAN_TCI 1

#define UDP_PAYLOAD_LEN 22

static __u8 pkt_skb_ext[ETH_HLEN + sizeof(struct iphdr) +
			sizeof(struct udphdr) + UDP_PAYLOAD_LEN];

/* Valid checksums, as in real traffic */
static void build_pkt(void)
{
	struct ethhdr *eth = (void *)pkt_skb_ext;
	struct iphdr *iph = (void *)(eth + 1);
	struct udphdr *udph = (void *)(iph + 1);

	eth->h_proto = htons(ETH_P_IP);

	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(sizeof(pkt_skb_ext) - ETH_HLEN);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = htonl(0x0a000001);
	iph->daddr = htonl(0x0a000002);
	iph->check = build_ip_csum(iph);

	udph->source = htons(4000);
	udph->dest = htons(4001);
	udph->len = htons(sizeof(*udph) + UDP_PAYLOAD_LEN);
	udph->check = build_udp_v4_csum(iph, udph);
}

/* The case that test_veth_skb() uses */
enum { CASE_ALL };

static const struct skb_ext_case {
	const char *name;
	struct xdp_skb_ext_vals want;
	bool del_hash;
} skb_ext_cases[] = {
	[CASE_ALL] = {
		.name = "all",
		.want = {
			.rx_hash = RX_HASH,
			.rx_hash_type = XDP_RSS_TYPE_L4_IPV4_TCP,
			.rx_vlan_proto = __bpf_constant_htons(ETH_P_8021Q),
			.rx_vlan_tci = RX_VLAN_TCI,
			.ip_summed = XDP_CHECKSUM_UNNECESSARY,
			.csum_level = 1,
			.fields = SKB_EXT_FIELD_HASH | SKB_EXT_FIELD_VLAN |
				  SKB_EXT_FIELD_CSUM,
		},
	},
	{
		.name = "none",
	},
	{
		.name = "hash_l4",
		.want = {
			.rx_hash = RX_HASH,
			.rx_hash_type = XDP_RSS_TYPE_L4_IPV4_TCP,
			.fields = SKB_EXT_FIELD_HASH,
		},
	},
	{
		.name = "hash_l3",
		.want = {
			.rx_hash = RX_HASH,
			.rx_hash_type = XDP_RSS_TYPE_L3_IPV4,
			.fields = SKB_EXT_FIELD_HASH,
		},
	},
	{
		.name = "del_hash",
		.del_hash = true,
	},
	{
		.name = "vlan",
		.want = {
			.rx_vlan_proto = __bpf_constant_htons(ETH_P_8021Q),
			.rx_vlan_tci = RX_VLAN_TCI,
			.fields = SKB_EXT_FIELD_VLAN,
		},
	},
	{
		.name = "vlan_ad",
		.want = {
			.rx_vlan_proto = __bpf_constant_htons(ETH_P_8021AD),
			.rx_vlan_tci = RX_VLAN_TCI,
			.fields = SKB_EXT_FIELD_VLAN,
		},
	},
	{
		.name = "csum_none",
		.want = {
			.ip_summed = XDP_CHECKSUM_NONE,
			.fields = SKB_EXT_FIELD_CSUM,
		},
	},
	{
		.name = "csum_level0",
		.want = {
			.ip_summed = XDP_CHECKSUM_UNNECESSARY,
			.fields = SKB_EXT_FIELD_CSUM,
		},
	},
	{
		.name = "csum_level3",
		.want = {
			.ip_summed = XDP_CHECKSUM_UNNECESSARY,
			.csum_level = 3,
			.fields = SKB_EXT_FIELD_CSUM,
		},
	},
};

/* The area of a reused page is not valid for the next packet */
static void test_live_frames(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    .repeat = 256,
	);
	struct test_xdp_skb_ext *skel;
	int prog_fd;

	skel = test_xdp_skb_ext__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_xdp_skb_ext__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.live_frames);
	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &opts), "test_run"))
		goto out;
	ASSERT_GT(skel->bss->reused_ok, 0, "reused_ok");
	ASSERT_EQ(skel->bss->reused_bad, 0, "reused_bad");
	ASSERT_EQ(skel->bss->store_err, 0, "store_err");
out:
	test_xdp_skb_ext__destroy(skel);
}

static void set_case(struct test_xdp_skb_ext *skel,
		     const struct skb_ext_case *c)
{
	skel->bss->want = c->want;
	skel->bss->del_hash = c->del_hash;
	memset(&skel->bss->have, 0, sizeof(skel->bss->have));
	skel->bss->store_err = 0;
	skel->bss->pkts_seen_tc = 0;
}

/* cpumap builds the skb in its kthread */
static bool wait_pkt(struct test_xdp_skb_ext *skel)
{
	int i;

	for (i = 0; i < 100; i++) {
		if (__atomic_load_n(&skel->bss->pkts_seen_tc, __ATOMIC_ACQUIRE))
			break;
		usleep(10000);
	}
	return ASSERT_EQ(skel->bss->pkts_seen_tc, 1, "pkts_seen_tc");
}

static void check_have(struct test_xdp_skb_ext *skel)
{
	const struct xdp_skb_ext_vals *want = &skel->bss->want;
	const struct xdp_skb_ext_have *have = &skel->bss->have;
	bool unnecessary = (want->fields & SKB_EXT_FIELD_CSUM) &&
			   want->ip_summed == XDP_CHECKSUM_UNNECESSARY;

	if (!wait_pkt(skel))
		return;
	ASSERT_EQ(skel->bss->store_err, 0, "store_err");
	ASSERT_EQ(have->hash, want->rx_hash, "hash");
	ASSERT_EQ(have->l4_hash, !!(want->rx_hash_type & XDP_RSS_TYPE_L4),
		  "l4_hash");
	ASSERT_EQ(have->vlan_present, !!(want->fields & SKB_EXT_FIELD_VLAN),
		  "vlan_present");
	ASSERT_EQ(have->vlan_proto, want->rx_vlan_proto, "vlan_proto");
	ASSERT_EQ(have->vlan_tci, want->rx_vlan_tci, "vlan_tci");
	ASSERT_EQ(have->ip_summed,
		  unnecessary ? CHECKSUM_UNNECESSARY : CHECKSUM_NONE,
		  "ip_summed");
	ASSERT_EQ(have->csum_level, unnecessary ? want->csum_level : 0,
		  "csum_level");
}

static void test_frames(struct test_xdp_skb_ext *skel, const char *path,
			enum xdp_skb_ext_deliver deliver, int ifindex)
{
	struct xdp_md ctx_in = { .data_end = sizeof(pkt_skb_ext),
				 .ingress_ifindex = ifindex };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = pkt_skb_ext,
		    .data_size_in = sizeof(pkt_skb_ext),
		    .ctx_in = &ctx_in,
		    .ctx_size_in = sizeof(ctx_in),
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    .repeat = 1,
	);
	int prog_fd = bpf_program__fd(skel->progs.xdp_store);
	char name[32];
	int i;

	skel->bss->deliver = deliver;
	for (i = 0; i < ARRAY_SIZE(skb_ext_cases); i++) {
		snprintf(name, sizeof(name), "%s_%s", path,
			 skb_ext_cases[i].name);
		if (!test__start_subtest(name))
			continue;
		set_case(skel, &skb_ext_cases[i]);
		if (ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &opts),
			      "test_run"))
			check_have(skel);
	}
}

/* The XDP program on the veth device gets an skb, not an xdp_frame */
static void test_veth_skb(struct test_xdp_skb_ext *skel, struct bpf_link *link,
			  int ifindex, enum xdp_skb_ext_deliver deliver)
{
	struct sockaddr_ll addr = {
		.sll_family = PF_PACKET,
		.sll_ifindex = ifindex,
		.sll_halen = ETH_ALEN,
	};
	const struct xdp_skb_ext_have *have = &skel->bss->have;
	int sock;

	skel->bss->deliver = deliver;
	if (!ASSERT_OK(bpf_link__update_program(link, skel->progs.xdp_store),
		       "update xdp_store"))
		return;

	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (!ASSERT_GE(sock, 0, "socket"))
		return;
	set_case(skel, &skb_ext_cases[CASE_ALL]);
	if (!ASSERT_EQ(sendto(sock, pkt_skb_ext, sizeof(pkt_skb_ext), 0,
			      (struct sockaddr *)&addr, sizeof(addr)),
		       sizeof(pkt_skb_ext), "sendto") ||
	    !wait_pkt(skel))
		goto out;
	if (deliver == DELIVER_CPUMAP) {
		check_have(skel);
		goto out;
	}
	ASSERT_EQ(skel->bss->store_err, 0, "store_err");
	ASSERT_NEQ(have->hash, RX_HASH, "hash");
	ASSERT_EQ(have->vlan_present, 0, "vlan_present");
	ASSERT_EQ(have->vlan_proto, 0, "vlan_proto");
	ASSERT_EQ(have->vlan_tci, 0, "vlan_tci");
	ASSERT_EQ(have->ip_summed, CHECKSUM_NONE, "ip_summed");
	ASSERT_EQ(have->csum_level, 0, "csum_level");
out:
	close(sock);
}

void test_xdp_skb_ext(void)
{
	RUN_TESTS(xdp_skb_ext_success);
	RUN_TESTS(xdp_skb_ext_failure);

	if (test__start_subtest("live_frames"))
		test_live_frames();
}

void test_xdp_skb_ext_to_skb(void)
{
	struct bpf_cpumap_val val = { .qsize = 192 };
	int ifindex_src, ifindex_dst, tc_prog_fd;
	struct xdp_dummy *skel_dummy = NULL;
	struct test_xdp_skb_ext *skel = NULL;
	struct bpf_link *link = NULL;
	struct netns_obj *ns = NULL;
	__u32 key = 0;

	build_pkt();

	ns = netns_new("xdp_skb_ext", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		return;

	SYS(out, "ip link add veth_src type veth peer name veth_dst");
	SYS(out, "ip link set dev veth_src up");
	SYS(out, "ip link set dev veth_dst up");
	/* GRO would verify the UDP checksum and change ip_summed */
	SYS(out, "ethtool -K veth_src gro off");
	SYS(out, "ethtool -K veth_dst gro off");

	ifindex_src = if_nametoindex("veth_src");
	ifindex_dst = if_nametoindex("veth_dst");
	if (!ASSERT_NEQ(ifindex_src, 0, "ifindex_src") ||
	    !ASSERT_NEQ(ifindex_dst, 0, "ifindex_dst"))
		goto out;

	skel = test_xdp_skb_ext__open();
	if (!ASSERT_OK_PTR(skel, "test_xdp_skb_ext__open"))
		goto out;
	skel->rodata->ifindex_out = ifindex_src;
	if (!ASSERT_OK(test_xdp_skb_ext__load(skel), "test_xdp_skb_ext__load"))
		goto out;

	/* pass and cpumap build the skb on veth_src, veth on veth_dst */
	tc_prog_fd = bpf_program__fd(skel->progs.tc_read_skb);
	if (tc_prog_attach("veth_src", tc_prog_fd, -1) ||
	    tc_prog_attach("veth_dst", tc_prog_fd, -1))
		goto out;

	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.cpu_map),
					   &key, &val, 0), "add cpumap entry"))
		goto out;

	skel_dummy = xdp_dummy__open_and_load();
	if (!ASSERT_OK_PTR(skel_dummy, "xdp_dummy__open_and_load"))
		goto out;

	/* veth_dst takes xdp_frames only with an XDP program */
	link = bpf_program__attach_xdp(skel_dummy->progs.xdp_dummy_prog,
				       ifindex_dst);
	if (!ASSERT_OK_PTR(link, "attach xdp_dummy"))
		goto out;

	test_frames(skel, "pass", DELIVER_PASS, ifindex_src);
	test_frames(skel, "cpumap", DELIVER_CPUMAP, ifindex_src);
	test_frames(skel, "veth", DELIVER_VETH, ifindex_src);
	if (test__start_subtest("veth_skb"))
		test_veth_skb(skel, link, ifindex_src, DELIVER_PASS);
	if (test__start_subtest("veth_skb_cpumap"))
		test_veth_skb(skel, link, ifindex_src, DELIVER_CPUMAP);

out:
	bpf_link__destroy(link);
	xdp_dummy__destroy(skel_dummy);
	test_xdp_skb_ext__destroy(skel);
	netns_free(ns);
}
