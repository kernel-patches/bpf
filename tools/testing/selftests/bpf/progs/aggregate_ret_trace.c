// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_testmod_aggregate_ret {
	__u64 lo;
	__u64 hi;
};

int fentry_hit;
int fexit_hit;
int fentry_multi_hit;

SEC("fentry/bpf_testmod:bpf_testmod_aggregate_ret_fn")
int BPF_PROG2(fentry_bpf_testmod_aggregate_ret_fn, __u64, lo, __u64, hi)
{
	fentry_hit++;
	return 0;
}

SEC("fexit/bpf_testmod:bpf_testmod_aggregate_ret_fn")
int BPF_PROG2(fexit_bpf_testmod_aggregate_ret_fn, __u64, lo, __u64, hi,
	      struct bpf_testmod_aggregate_ret, ret)
{
	fexit_hit += ret.lo == lo && ret.hi == hi;
	return 0;
}

SEC("fentry.multi/bpf_testmod:bpf_testmod_aggregate_ret_i128_fn")
int BPF_PROG(fentry_multi)
{
	fentry_multi_hit++;
	return 0;
}

SEC("fexit.multi/bpf_testmod:bpf_testmod_aggregate_ret_i128_fn")
int BPF_PROG(fexit_multi)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
