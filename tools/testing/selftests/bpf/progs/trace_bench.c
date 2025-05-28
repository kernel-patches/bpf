// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 bench_result;

SEC("fexit.multi/bpf_testmod_bench_run")
int BPF_PROG(fexit_bench_done)
{
	__u64 ret = 0;

	bpf_get_func_ret(ctx, &ret);
	bench_result = ret;

	return 0;
}
