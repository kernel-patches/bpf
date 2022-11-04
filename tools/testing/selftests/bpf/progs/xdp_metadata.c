// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

extern void bpf_xdp_metadata_export_to_skb(const struct xdp_md *ctx) __ksym;
extern int bpf_xdp_metadata_rx_timestamp_supported(const struct xdp_md *ctx) __ksym;
extern const __u64 bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx) __ksym;

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	void *data, *data_meta;
	struct ethhdr *eth = NULL;
	struct udphdr *udp = NULL;
	struct iphdr *iph = NULL;
	void *data_end;
	int ret;

	/* Exercise xdp -> skb metadata path by diverting some traffic
	 * into the kernel (UDP destination port 9081).
	 */

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if (eth + 1 < data_end) {
		if (eth->h_proto == bpf_htons(ETH_P_IP)) {
			iph = (void *)(eth + 1);
			if (iph + 1 < data_end && iph->protocol == IPPROTO_UDP)
				udp = (void *)(iph + 1);
		}
		if (udp && udp + 1 > data_end)
			udp = NULL;
	}
	if (udp && udp->dest == bpf_htons(9081)) {
		bpf_xdp_metadata_export_to_skb(ctx);
		bpf_printk("exporting metadata to skb for UDP port 9081");
		/*return bpf_redirect(ifindex, BPF_F_INGRESS);*/
		return XDP_PASS;
	}

	if (bpf_xdp_metadata_rx_timestamp_supported(ctx)) {
		__u64 rx_timestamp = bpf_xdp_metadata_rx_timestamp(ctx);

		if (rx_timestamp) {
			ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(rx_timestamp));
			if (ret != 0)
				return XDP_DROP;

			data = (void *)(long)ctx->data;
			data_meta = (void *)(long)ctx->data_meta;

			if (data_meta + sizeof(rx_timestamp) > data)
				return XDP_DROP;

			*(__u64 *)data_meta = rx_timestamp;
		}
	}

	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
