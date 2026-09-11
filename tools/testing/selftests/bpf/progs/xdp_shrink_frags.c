// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int shrink_ran;

SEC("xdp.frags")
int xdp_shrink(struct xdp_md *ctx)
{
	/*
	 * Runs on both skb-backed XDP paths (generic XDP via tun, and veth):
	 * the nonlinear skb is cow'd into page_pool memory before we run, so
	 * shrinking the tail releases a whole frag that has to go back to that
	 * pool. The counter only tells us the program ran and the helper
	 * succeeded -- a linear buff returns 0 as well -- it does not prove a
	 * frag was released.
	 */
	if (bpf_xdp_adjust_tail(ctx, -3000) == 0)
		__sync_fetch_and_add(&shrink_ran, 1);
	return XDP_PASS;
}

SEC("xdp.frags")
int xdp_tx(struct xdp_md *ctx)
{
	/*
	 * Bounce the frame back. On veth this turns the buff into an
	 * xdp_frame, which is where a buff-scoped page_pool tag must not leak
	 * into the frame handed to the peer.
	 */
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
