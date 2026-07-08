// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_dispatcher_attached(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp")
int xdp_dispatcher_unattached(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
