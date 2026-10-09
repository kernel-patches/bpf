// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

long odd_a, odd_lo, odd_hi, odd_b, odd_ret;

SEC("fentry/callee_odd")
int odd_entry(unsigned long long *ctx)
{
	odd_a = ctx[0];
	odd_lo = ctx[1];
	odd_hi = ctx[2];
	odd_b = ctx[3];
	return 0;
}

SEC("fexit/callee_odd")
int odd_exit(unsigned long long *ctx)
{
	odd_ret = ctx[4];
	return 0;
}

long stack_g, stack_lo, stack_hi, stack_i, stack_ret;

SEC("fentry/callee_stack")
int stack_entry(unsigned long long *ctx)
{
	stack_g = ctx[6];
	stack_lo = ctx[7];
	stack_hi = ctx[8];
	stack_i = ctx[9];
	return 0;
}

SEC("fexit/callee_stack")
int stack_exit(unsigned long long *ctx)
{
	stack_ret = ctx[10];
	return 0;
}

char _license[] SEC("license") = "GPL";
