// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
const volatile int ifindex_out;
const volatile __u8 expect_dst[ETH_ALEN];
volatile int pkts_seen = 0;
volatile int retcode = XDP_DROP;

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *xdp)
{
	if (retcode == XDP_REDIRECT)
		bpf_redirect(ifindex_out, 0);
	return retcode++;
}

SEC("xdp")
int xdp_count_pkts(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *iph = (void *)(eth + 1);
	struct udphdr *udp = (void *)(iph + 1);
	__u8 *payload = (void *)(udp + 1);
	int i;

	if (payload + 1 > data_end)
		return XDP_ABORTED;

	if (iph->nexthdr == IPPROTO_UDP && *payload == 0x42)
		pkts_seen++;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
