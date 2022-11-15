// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_hw_metadata.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

extern int bpf_xdp_metadata_export_to_skb(const struct xdp_md *ctx) __ksym;
extern int bpf_xdp_metadata_rx_timestamp_supported(const struct xdp_md *ctx) __ksym;
extern const __u64 bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx) __ksym;

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	void *data, *data_meta, *data_end;
	struct ipv6hdr *ip6h = NULL;
	struct ethhdr *eth = NULL;
	struct udphdr *udp = NULL;
	struct xsk_metadata *meta;
	struct iphdr *iph = NULL;
	int ret;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if (eth + 1 < data_end) {
		if (eth->h_proto == bpf_htons(ETH_P_IP)) {
			iph = (void *)(eth + 1);
			if (iph + 1 < data_end && iph->protocol == IPPROTO_UDP)
				udp = (void *)(iph + 1);
		}
		if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
			ip6h = (void *)(eth + 1);
			if (ip6h + 1 < data_end && ip6h->nexthdr == IPPROTO_UDP)
				udp = (void *)(ip6h + 1);
		}
		if (udp && udp + 1 > data_end)
			udp = NULL;
	}

	if (!udp)
		return XDP_PASS;

	if (udp->dest == bpf_htons(9092)) {
		bpf_printk("forwarding UDP:9092 to socket listener");

		if (!bpf_xdp_metadata_export_to_skb(ctx)) {
			bpf_printk("bpf_xdp_metadata_export_to_skb failed");
			return XDP_DROP;
		}

		return XDP_PASS;
	}

	if (udp->dest != bpf_htons(9091))
		return XDP_PASS;

	bpf_printk("forwarding UDP:9091 to AF_XDP");

	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xsk_metadata));
	if (ret != 0) {
		bpf_printk("bpf_xdp_adjust_meta returned %d", ret);
		return XDP_PASS;
	}

	data = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;
	meta = data_meta;

	if (meta + 1 > data) {
		bpf_printk("bpf_xdp_adjust_meta doesn't appear to work");
		return XDP_PASS;
	}


	if (bpf_xdp_metadata_rx_timestamp_supported(ctx)) {
		meta->rx_timestamp_supported = 1;
		meta->rx_timestamp = bpf_xdp_metadata_rx_timestamp(ctx);
		bpf_printk("populated rx_timestamp with %u", meta->rx_timestamp);
	}

	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
