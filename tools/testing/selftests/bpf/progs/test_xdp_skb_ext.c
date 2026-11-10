// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include "xdp_skb_ext.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Written to the first byte of the packet. A reused page keeps it. */
#define MARK_STORED 0xaa

int reused_ok, reused_bad, store_err;

SEC("xdp")
int live_frames(struct xdp_md *ctx)
{
	__u8 *mark = (void *)(long)ctx->data;

	if (mark + 1 > (__u8 *)(long)ctx->data_end)
		return XDP_DROP;
	/* A reused page: MAX_META_LEN fits only if its area was reset */
	if (*mark == MARK_STORED) {
		if (bpf_xdp_adjust_meta(ctx, -MAX_META_LEN)) {
			reused_bad++;
		} else {
			reused_ok++;
			bpf_xdp_adjust_meta(ctx, MAX_META_LEN);
		}
	}
	if (bpf_xdp_skb_ext_store_rx_hash(ctx, 1, XDP_RSS_TYPE_L4_IPV4_TCP) ||
	    bpf_xdp_skb_ext_store_rx_vlan(ctx, bpf_htons(ETH_P_8021Q), 1) ||
	    bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_UNNECESSARY,
					  SKB_MAX_CSUM_LEVEL))
		store_err++;

	mark = (void *)(long)ctx->data;
	if (mark + 1 > (__u8 *)(long)ctx->data_end)
		return XDP_DROP;
	*mark = MARK_STORED;
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
