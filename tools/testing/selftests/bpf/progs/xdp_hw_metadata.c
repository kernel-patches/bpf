// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "xdp_metadata.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} tx_compl_buf SEC(".maps");

__u64 pkts_skip = 0;
__u64 pkts_tx_skip = 0;
__u64 pkts_fail = 0;
__u64 pkts_redir = 0;
__u64 pkts_fail_tx = 0;
__u64 pkts_fail_l4_csum = 0;
__u64 pkts_ringbuf_full = 0;

int ifindex = -1;
__u64 net_cookie = -1;

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					 __u64 *timestamp) __ksym;
extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
				    enum xdp_rss_hash_type *rss_type) __ksym;
extern int bpf_devtx_request_tx_timestamp(const struct devtx_ctx *ctx) __ksym;
extern int bpf_devtx_tx_timestamp(const struct devtx_ctx *ctx, __u64 *timestamp) __ksym;
extern int bpf_devtx_request_l4_csum(const struct devtx_ctx *ctx,
				     u16 csum_start, u16 csum_offset) __ksym;

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	void *data, *data_meta, *data_end;
	struct ipv6hdr *ip6h = NULL;
	struct ethhdr *eth = NULL;
	struct udphdr *udp = NULL;
	struct iphdr *iph = NULL;
	struct xdp_meta *meta;
	int err;

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

	if (!udp) {
		__sync_add_and_fetch(&pkts_skip, 1);
		return XDP_PASS;
	}

	/* Forwarding UDP:9091 to AF_XDP */
	if (udp->dest != bpf_htons(9091)) {
		__sync_add_and_fetch(&pkts_skip, 1);
		return XDP_PASS;
	}

	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta));
	if (err) {
		__sync_add_and_fetch(&pkts_fail, 1);
		return XDP_PASS;
	}

	data = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;
	meta = data_meta;

	if (meta + 1 > data) {
		__sync_add_and_fetch(&pkts_fail, 1);
		return XDP_PASS;
	}

	err = bpf_xdp_metadata_rx_timestamp(ctx, &meta->rx_timestamp);
	if (!err)
		meta->xdp_timestamp = bpf_ktime_get_tai_ns();
	else
		meta->rx_timestamp = 0; /* Used by AF_XDP as not avail signal */

	err = bpf_xdp_metadata_rx_hash(ctx, &meta->rx_hash, &meta->rx_hash_type);
	if (err < 0)
		meta->rx_hash_err = err; /* Used by AF_XDP as no hash signal */

	__sync_add_and_fetch(&pkts_redir, 1);
	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

/* This is not strictly required; only to showcase how to access the payload. */
static __always_inline bool tx_filter(const struct devtx_ctx *devtx,
				      const void *data, __be16 *proto)
{
	int port_offset = sizeof(struct ethhdr) + offsetof(struct udphdr, source);
	struct ethhdr eth = {};
	struct udphdr udp = {};

	bpf_probe_read_kernel(&eth.h_proto, sizeof(eth.h_proto),
			      data + offsetof(struct ethhdr, h_proto));

	*proto = eth.h_proto;
	if (eth.h_proto == bpf_htons(ETH_P_IP)) {
		port_offset += sizeof(struct iphdr);
	} else if (eth.h_proto == bpf_htons(ETH_P_IPV6)) {
		port_offset += sizeof(struct ipv6hdr);
	} else {
		__sync_add_and_fetch(&pkts_tx_skip, 1);
		return false;
	}

	bpf_probe_read_kernel(&udp.source, sizeof(udp.source), data + port_offset);

	/* Replies to UDP:9091 */
	if (udp.source != bpf_htons(9091)) {
		__sync_add_and_fetch(&pkts_tx_skip, 1);
		return false;
	}

	return true;
}

static inline bool my_netdev(const struct devtx_ctx *devtx)
{
	static struct net_device *netdev;

	if (netdev)
		return netdev == devtx->netdev;

	if (devtx->netdev->ifindex != ifindex)
		return false;
	if (devtx->netdev->nd_net.net->net_cookie != net_cookie)
		return false;

	netdev = devtx->netdev;
	return true;
}

static inline int udpoff(__be16 proto)
{
	if (proto == bpf_htons(ETH_P_IP))
		return sizeof(struct ethhdr) + sizeof(struct iphdr);
	else if (proto == bpf_htons(ETH_P_IPV6))
		return sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	else
		return 0;
}

static inline int tx_submit(const struct devtx_ctx *devtx, const void *data, u8 meta_len)
{
	struct xdp_tx_meta meta = {};
	__be16 proto = 0;
	int off, ret;

	if (!my_netdev(devtx))
		return 0;
	if (meta_len != TX_META_LEN)
		return 0;

	bpf_probe_read_kernel(&meta, sizeof(meta), data - TX_META_LEN);
	if (!meta.request_timestamp)
		return 0;

	if (!tx_filter(devtx, data, &proto))
		return 0;

	ret = bpf_devtx_request_tx_timestamp(devtx);
	if (ret < 0)
		__sync_add_and_fetch(&pkts_fail_tx, 1);

	off = udpoff(proto);
	if (!off)
		return 0;

	ret = bpf_devtx_request_l4_csum(devtx, off, off + offsetof(struct udphdr, check));
	if (ret < 0)
		__sync_add_and_fetch(&pkts_fail_l4_csum, 1);

	return 0;
}

SEC("?fentry")
int BPF_PROG(tx_submit_xdp, const struct devtx_ctx *devtx, const struct xdp_frame *xdpf)
{
	return tx_submit(devtx, xdpf->data, xdpf->metasize);
}

SEC("?fentry")
int BPF_PROG(tx_submit_skb, const struct devtx_ctx *devtx, const struct sk_buff *skb)
{
	return tx_submit(devtx, skb->data, devtx->sinfo->meta_len);
}

static inline int tx_complete(const struct devtx_ctx *devtx, const void *data, u8 meta_len)
{
	struct xdp_tx_meta meta = {};
	struct devtx_sample *sample;
	struct udphdr udph;
	__be16 proto = 0;
	int off;

	if (!my_netdev(devtx))
		return 0;
	if (meta_len != TX_META_LEN)
		return 0;

	bpf_probe_read_kernel(&meta, sizeof(meta), data - TX_META_LEN);
	if (!meta.request_timestamp)
		return 0;

	if (!tx_filter(devtx, data, &proto))
		return 0;

	off = udpoff(proto);
	if (!off)
		return 0;

	bpf_probe_read_kernel(&udph, sizeof(udph), data + off);

	sample = bpf_ringbuf_reserve(&tx_compl_buf, sizeof(*sample), 0);
	if (!sample) {
		__sync_add_and_fetch(&pkts_ringbuf_full, 1);
		return 0;
	}

	sample->timestamp_retval = bpf_devtx_tx_timestamp(devtx, &sample->hw_timestamp);
	sample->sw_complete_timestamp = bpf_ktime_get_tai_ns();
	sample->tx_csum = udph.check;

	bpf_ringbuf_submit(sample, 0);

	return 0;
}

SEC("?fentry")
int BPF_PROG(tx_complete_xdp, const struct devtx_ctx *devtx, const struct xdp_frame *xdpf)
{
	return tx_complete(devtx, xdpf->data, xdpf->metasize);
}

SEC("?fentry")
int BPF_PROG(tx_complete_skb, const struct devtx_ctx *devtx, const struct sk_buff *skb)
{
	return tx_complete(devtx, skb->data, devtx->sinfo->meta_len);
}

char _license[] SEC("license") = "GPL";
