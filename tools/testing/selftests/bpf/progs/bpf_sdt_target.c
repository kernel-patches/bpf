// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../../../../tools/lib/bpf/bpf_sdt.h"

BPF_SDT_DECLARE(tc_probe);
BPF_SDT_DECLARE1(xdp_probe_ctx, struct xdp_md *);
BPF_SDT_DECLARE2(xdp_probe_len_ret, int, int);

static __noinline int xdp_process(struct xdp_md *ctx)
{
	BPF_SDT_PROBE1(xdp_probe_ctx, ctx);
	return XDP_PASS;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	int len = (int)(ctx->data_end - ctx->data);

	BPF_SDT_PROBE2(xdp_probe_len_ret, len, XDP_PASS);

	return xdp_process(ctx);
}

SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	BPF_SDT_PROBE(tc_probe);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
