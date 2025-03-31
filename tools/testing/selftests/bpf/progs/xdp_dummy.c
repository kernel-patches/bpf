// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_dummy"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int head_size;

SEC("xdp")
int xdp_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp")
int xdp_dummy_adjust_head(struct xdp_md *ctx)
{
	if (bpf_xdp_adjust_head(ctx, -head_size))
		return XDP_DROP;

	if (bpf_xdp_adjust_head(ctx, head_size))
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
