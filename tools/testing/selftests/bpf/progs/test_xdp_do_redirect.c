// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
const volatile int ifindex_out;
const volatile __u8 expect_dst[ETH_ALEN];
volatile int pkts_seen = 0;

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *xdp)
{
	return bpf_redirect(ifindex_out, 0);
}

SEC("xdp")
int xdp_count_pkts(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	int i;

	if (eth + 1 > data_end)
		return XDP_ABORTED;

	for (i = 0; i < ETH_ALEN; i++)
		if (expect_dst[i] != eth->h_dest[i])
			return XDP_ABORTED;
	pkts_seen++;
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
