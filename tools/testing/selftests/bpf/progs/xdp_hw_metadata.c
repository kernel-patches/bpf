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
	__uint(max_entries, 10);
} tx_compl_buf SEC(".maps");

__u64 pkts_skip = 0;
__u64 pkts_fail = 0;
__u64 pkts_redir = 0;
__u64 pkts_fail_tx = 0;
__u64 pkts_ringbuf_full = 0;

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					 __u64 *timestamp) __ksym;
extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
				    enum xdp_rss_hash_type *rss_type) __ksym;
extern int bpf_devtx_sb_request_timestamp(const struct devtx_frame *ctx) __ksym;
extern int bpf_devtx_cp_timestamp(const struct devtx_frame *ctx, __u64 *timestamp) __ksym;

extern int bpf_devtx_sb_attach(int ifindex, int prog_fd) __ksym;
extern int bpf_devtx_cp_attach(int ifindex, int prog_fd) __ksym;

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

SEC("fentry/devtx_sb")
int BPF_PROG(devtx_sb, const struct devtx_frame *frame)
{
	int ret;

	ret = bpf_devtx_sb_request_timestamp(frame);
	if (ret < 0)
		__sync_add_and_fetch(&pkts_fail_tx, 1);

	return 0;
}

SEC("fentry/devtx_cp")
int BPF_PROG(devtx_cp, const struct devtx_frame *frame)
{
	struct devtx_sample *sample;

	sample = bpf_ringbuf_reserve(&tx_compl_buf, sizeof(*sample), 0);
	if (!sample) {
		__sync_add_and_fetch(&pkts_ringbuf_full, 1);
		return 0;
	}

	sample->timestamp_retval = bpf_devtx_cp_timestamp(frame, &sample->timestamp);

	bpf_ringbuf_submit(sample, 0);

	return 0;
}

SEC("syscall")
int attach_prog(struct devtx_attach_args *ctx)
{
	ctx->devtx_sb_retval = bpf_devtx_sb_attach(ctx->ifindex, ctx->devtx_sb_prog_fd);
	ctx->devtx_cp_retval = bpf_devtx_cp_attach(ctx->ifindex, ctx->devtx_cp_prog_fd);
	return 0;
}

SEC("syscall")
int detach_prog(struct devtx_attach_args *ctx)
{
	ctx->devtx_sb_retval = bpf_devtx_sb_attach(ctx->ifindex, -1);
	ctx->devtx_cp_retval = bpf_devtx_cp_attach(ctx->ifindex, -1);
	return 0;
}

char _license[] SEC("license") = "GPL";
