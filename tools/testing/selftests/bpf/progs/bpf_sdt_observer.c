// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile int xdp_len;
volatile int xdp_ret;

SEC("bpf_sdt")
int BPF_PROG(tc_trace_prog)
{
	return 0;
}

SEC("bpf_sdt")
int BPF_PROG(xdp_trace_prog, int len, int ret)
{
	xdp_len = len;
	xdp_ret = ret;
	return 0;
}

SEC("bpf_sdt")
int BPF_PROG(subprog_trace_prog, struct xdp_md *xdp_ctx)
{
	xdp_len = bpf_xdp_get_buff_len((struct xdp_md *)xdp_ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
