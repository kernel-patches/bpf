// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct bpf_fib_lookup fib_params = {};
int fib_lookup_ret = 0;
int lookup_flags = 0;

SEC("tc")
int fib_lookup(struct __sk_buff *skb)
{
	fib_lookup_ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params),
					lookup_flags);

	return TC_ACT_SHOT;
}

SEC("xdp")
int fib_lookup_xdp(struct xdp_md *ctx)
{
	fib_lookup_ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),
					lookup_flags);

	return XDP_DROP;
}

int redirected = 0;
int passed = 0;
int delivered = 0;

SEC("xdp")
int fib_lookup_redirect(struct xdp_md *ctx)
{
	struct bpf_fib_lookup params = fib_params;
	long ret;

	ret = bpf_fib_lookup(ctx, &params, sizeof(params), lookup_flags);
	if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
		redirected++;
		return bpf_redirect(params.ifindex, 0);
	}

	passed++;
	return XDP_PASS;
}

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
	delivered++;
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
