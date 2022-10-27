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

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
