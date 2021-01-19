// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	return bpf_redirect_xsk(ctx, XDP_DROP);
}

