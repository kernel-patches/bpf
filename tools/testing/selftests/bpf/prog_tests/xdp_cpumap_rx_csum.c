// SPDX-License-Identifier: GPL-2.0
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "test_progs.h"
#include "network_helpers.h"
#include <bpf/bpf_endian.h>
#include "test_xdp_cpumap_rx_csum.skel.h"

#define TEST_NS		"xdp_cm_csum_ns"
#define UDP_TEST_PORT	7777

/* Kernel skb->ip_summed values, not exported to userspace headers. */
#define CHECKSUM_NONE		0
#define CHECKSUM_UNNECESSARY	1

struct udp_pkt {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct udphdr udp;
	__u8 payload[16];
} __packed;

static struct udp_pkt pkt = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.eth.h_dest = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	.eth.h_source = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
	.iph.version = 6,
	.iph.nexthdr = IPPROTO_UDP,
	.iph.payload_len = __bpf_constant_htons(sizeof(struct udphdr) + 16),
	.iph.hop_limit = 64,
	.udp.source = __bpf_constant_htons(1),
	.udp.dest = __bpf_constant_htons(UDP_TEST_PORT),
	.udp.len = __bpf_constant_htons(sizeof(struct udphdr) + 16),
};

/* Inject one frame on veth0; it is received on veth1 where native XDP
 * redirects it into the cpumap. Report the ip_summed the rebuilt skb carried.
 */
static int inject_and_observe(struct test_xdp_cpumap_rx_csum *skel, int sfd,
			      int ifindex_src, bool assert_csum, int *ip_summed)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_ifindex = ifindex_src,
		.sll_halen = 0,
	};
	int i, n;

	skel->bss->assert_csum = assert_csum;
	skel->bss->seen = false;
	skel->data->observed_ip_summed = -1;

	n = sendto(sfd, &pkt, sizeof(pkt), 0, (void *)&sll, sizeof(sll));
	if (!ASSERT_EQ(n, sizeof(pkt), "sendto"))
		return -1;

	/* The skb is built asynchronously by the cpumap kthread. */
	for (i = 0; i < 20 && !skel->bss->seen; i++)
		usleep(50000);

	if (!ASSERT_TRUE(skel->bss->seen, "skb built from frame"))
		return -1;

	*ip_summed = skel->data->observed_ip_summed;
	return 0;
}

void test_xdp_cpumap_rx_csum(void)
{
	struct test_xdp_cpumap_rx_csum *skel = NULL;
	struct bpf_cpumap_val val = { .qsize = 192 };
	struct bpf_link *fexit_link = NULL;
	struct nstoken *nstoken = NULL;
	int err, map_fd, ifindex_dst = 0, ifindex_src, sfd = -1, ip_summed;
	bool xdp_attached = false;
	__u32 idx = 0;

	SYS(out, "ip netns add %s", TEST_NS);
	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto out;

	/* veth pair: a frame TX'd on veth0 is RX'd on veth1. */
	SYS(out, "ip link add veth0 type veth peer name veth1");
	SYS(out, "ip link set veth0 up");
	SYS(out, "ip link set veth1 up");

	skel = test_xdp_cpumap_rx_csum__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;

	/* cpumap entry without a program: a plain redirect that forces the
	 * frame->skb conversion in __xdp_build_skb_from_frame().
	 */
	map_fd = bpf_map__fd(skel->maps.cpu_map);
	err = bpf_map_update_elem(map_fd, &idx, &val, 0);
	if (!ASSERT_OK(err, "cpumap update"))
		goto out;

	ifindex_dst = if_nametoindex("veth1");
	ifindex_src = if_nametoindex("veth0");
	if (!ASSERT_GT(ifindex_dst, 0, "veth1 ifindex") ||
	    !ASSERT_GT(ifindex_src, 0, "veth0 ifindex"))
		goto out;

	/* Native XDP so the redirect goes through xdp_convert_buff_to_frame(),
	 * which propagates the rx-csum flag into the frame. Generic mode would
	 * redirect a ready-made skb and never hit our code path.
	 */
	err = bpf_xdp_attach(ifindex_dst, bpf_program__fd(skel->progs.xdp_redir),
			     XDP_FLAGS_DRV_MODE, NULL);
	if (!ASSERT_OK(err, "attach native xdp"))
		goto out;
	xdp_attached = true;

	fexit_link = bpf_program__attach(skel->progs.on_build);
	if (!ASSERT_OK_PTR(fexit_link, "attach fexit"))
		goto out;

	sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (!ASSERT_GE(sfd, 0, "AF_PACKET socket"))
		goto out;

	/* Program asserts the checksum -> CHECKSUM_UNNECESSARY. */
	if (!inject_and_observe(skel, sfd, ifindex_src, true, &ip_summed))
		ASSERT_EQ(ip_summed, CHECKSUM_UNNECESSARY,
			  "ip_summed marked unnecessary");

	/* No assertion -> skb is left CHECKSUM_NONE for the stack to validate. */
	if (!inject_and_observe(skel, sfd, ifindex_src, false, &ip_summed))
		ASSERT_EQ(ip_summed, CHECKSUM_NONE, "ip_summed left none");

out:
	if (sfd >= 0)
		close(sfd);
	bpf_link__destroy(fexit_link);
	if (xdp_attached)
		bpf_xdp_detach(ifindex_dst, XDP_FLAGS_DRV_MODE, NULL);
	test_xdp_cpumap_rx_csum__destroy(skel);
	if (nstoken)
		close_netns(nstoken);
	SYS_NOFAIL("ip netns del %s", TEST_NS);
}
