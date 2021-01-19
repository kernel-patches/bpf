// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 32);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}
