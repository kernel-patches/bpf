// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

extern void bpf_xdp_store_rx_hash(struct xdp_md *ctx, u32 hash,
				  enum xdp_rss_hash_type rss_type) __ksym;
extern void bpf_xdp_store_rx_ts(struct xdp_md *ctx, __u64 ts) __ksym;

#define RX_TIMESTAMP	0x12345678
#define RX_HASH		0x1234

#define ETH_ALEN	6
#define ETH_P_IP	0x0800

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_devmap_val));
	__uint(max_entries, 1);
} dev_map SEC(".maps");

SEC("xdp")
int xdp_rxmeta_redirect(struct xdp_md *ctx)
{
	__u8 src_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x01 };
	__u8 dst_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x02 };
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eh = data;

	if (eh + 1 > (struct ethhdr *)data_end)
		return XDP_DROP;

	if (eh->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	__builtin_memcpy(eh->h_source, src_mac, ETH_ALEN);
	__builtin_memcpy(eh->h_dest, dst_mac, ETH_ALEN);

	bpf_xdp_store_rx_hash(ctx, RX_HASH, XDP_RSS_L4_TCP);
	bpf_xdp_store_rx_ts(ctx, RX_TIMESTAMP);

	return bpf_redirect_map(&dev_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
