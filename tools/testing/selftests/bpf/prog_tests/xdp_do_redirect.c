// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include "test_xdp_do_redirect.skel.h"

#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			goto fail;				\
	})

struct udp_packet {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct udphdr udp;
	__u8 payload[64 - sizeof(struct udphdr)
		     - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __packed;

static struct udp_packet pkt_udp = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.eth.h_dest = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	.eth.h_source = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
	.iph.version = 6,
	.iph.nexthdr = IPPROTO_UDP,
	.iph.payload_len = bpf_htons(sizeof(struct udp_packet)
				     - offsetof(struct udp_packet, udp)),
	.iph.hop_limit = 2,
	.iph.saddr.s6_addr16 = {bpf_htons(0xfc00), 0, 0, 0, 0, 0, 0, bpf_htons(1)},
	.iph.daddr.s6_addr16 = {bpf_htons(0xfc00), 0, 0, 0, 0, 0, 0, bpf_htons(2)},
	.udp.source = bpf_htons(1),
	.udp.dest = bpf_htons(1),
	.udp.len = bpf_htons(sizeof(struct udp_packet)
			     - offsetof(struct udp_packet, udp)),
	.payload = {0x42}, /* receiver XDP program matches on this */
};

#define NUM_PKTS 3
void test_xdp_do_redirect(void)
{
	struct test_xdp_do_redirect *skel = NULL;
	struct xdp_md ctx_in = { .data_end = sizeof(pkt_udp) };
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = &pkt_udp,
			    .data_size_in = sizeof(pkt_udp),
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
			    .repeat = NUM_PKTS,
		);
	int err, prog_fd, ifindex_src, ifindex_dst;
	struct bpf_link *link;

	skel = test_xdp_do_redirect__open();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	/* We setup a veth pair that we can not only XDP_REDIRECT packets
	 * between, but also route them. The test packet (defined above) has
	 * address information so it will be routed back out the same interface
	 * after it has been received, which will allow it to be picked up by
	 * the XDP program on the destination interface.
	 *
	 * The XDP program we run with bpf_prog_run() will cycle through all
	 * four return codes (DROP/PASS/TX/REDIRECT), so we should end up with
	 * NUM_PKTS - 1 packets seen on the dst iface. We match the packets on
	 * the UDP payload.
	 */
	SYS("ip link add veth_src type veth peer name veth_dst");
	SYS("ip link set dev veth_src address 00:11:22:33:44:55");
	SYS("ip link set dev veth_dst address 66:77:88:99:aa:bb");
	SYS("ip link set dev veth_src up");
	SYS("ip link set dev veth_dst up");
	SYS("ip addr add dev veth_src fc00::1/64");
	SYS("ip addr add dev veth_dst fc00::2/64");
	SYS("ip neigh add fc00::2 dev veth_src lladdr 66:77:88:99:aa:bb");
	SYS("sysctl -w net.ipv6.conf.all.forwarding=1");

	ifindex_src = if_nametoindex("veth_src");
	ifindex_dst = if_nametoindex("veth_dst");
	if (!ASSERT_NEQ(ifindex_src, 0, "ifindex_src") ||
	    !ASSERT_NEQ(ifindex_dst, 0, "ifindex_dst"))
		goto fail;

	memcpy(skel->rodata->expect_dst, &pkt_udp.eth.h_dest, ETH_ALEN);
	skel->rodata->ifindex_out = ifindex_src;
	ctx_in.ingress_ifindex = ifindex_src;

	if (!ASSERT_OK(test_xdp_do_redirect__load(skel), "load"))
		goto fail;

	link = bpf_program__attach_xdp(skel->progs.xdp_count_pkts, ifindex_dst);
	if (!ASSERT_OK_PTR(link, "prog_attach"))
		goto fail;
	skel->links.xdp_count_pkts = link;

	prog_fd = bpf_program__fd(skel->progs.xdp_redirect_notouch);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "prog_run"))
		goto fail;

	/* wait for the packets to be flushed */
	kern_sync_rcu();

	ASSERT_EQ(skel->bss->pkts_seen, NUM_PKTS - 1, "pkt_count");
fail:
	system("ip link del dev veth_src");
	test_xdp_do_redirect__destroy(skel);
}
