// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int shrink_ran;

SEC("xdp.frags")
int xdp_shrink(struct xdp_md *ctx)
{
	/*
	 * The program is loaded with BPF_F_XDP_HAS_FRAGS (xdp.frags), so a
	 * nonlinear skb entering generic XDP is cow'd into page_pool memory
	 * before we run. Shrinking the tail far enough releases at least one
	 * whole frag, which must be returned to its page_pool. Count only a
	 * successful shrink so a too-small frame (e.g. ARP) does not satisfy
	 * the test.
	 */
	if (bpf_xdp_adjust_tail(ctx, -3000) == 0)
		__sync_fetch_and_add(&shrink_ran, 1);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
