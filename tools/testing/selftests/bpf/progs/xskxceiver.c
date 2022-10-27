// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

extern int bpf_xdp_metadata_have_rx_timestamp(struct xdp_md *ctx) __ksym;
extern __u32 bpf_xdp_metadata_rx_timestamp(struct xdp_md *ctx) __ksym;

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	void *data, *data_meta;
	__u32 rx_timestamp;
	int ret;

	if (bpf_xdp_metadata_have_rx_timestamp(ctx)) {
		ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(__u32));
		if (ret != 0)
			return XDP_DROP;

		data = (void *)(long)ctx->data;
		data_meta = (void *)(long)ctx->data_meta;

		if (data_meta + sizeof(__u32) > data)
			return XDP_DROP;

		rx_timestamp = bpf_xdp_metadata_rx_timestamp(ctx);
		__builtin_memcpy(data_meta, &rx_timestamp, sizeof(__u32));
	}

	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
