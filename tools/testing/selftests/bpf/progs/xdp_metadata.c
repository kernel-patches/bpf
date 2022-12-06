// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#include "xdp_metadata.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_arr SEC(".maps");

extern bool bpf_xdp_metadata_rx_timestamp_supported(const struct xdp_md *ctx) __ksym;
extern __u64 bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx) __ksym;
extern bool bpf_xdp_metadata_rx_hash_supported(const struct xdp_md *ctx) __ksym;
extern __u32 bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx) __ksym;

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	void *data, *data_meta;
	struct xdp_meta *meta;
	int ret;

	/* Reserve enough for all custom metadata. */

	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta));
	if (ret != 0)
		return XDP_DROP;

	data = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;

	if (data_meta + sizeof(struct xdp_meta) > data)
		return XDP_DROP;

	meta = data_meta;

	/* Export metadata. */

	if (bpf_xdp_metadata_rx_timestamp_supported(ctx))
		meta->rx_timestamp = bpf_xdp_metadata_rx_timestamp(ctx);

	if (bpf_xdp_metadata_rx_hash_supported(ctx))
		meta->rx_hash = bpf_xdp_metadata_rx_hash(ctx);

	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

SEC("?freplace/rx")
int freplace_rx(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
