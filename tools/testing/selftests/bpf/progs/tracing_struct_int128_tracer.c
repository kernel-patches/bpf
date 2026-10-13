// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/*
 * A struct holding an __int128 fills its two slots in memory order, so
 * which slot holds the low half depends on the byte order.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LO 0
#define HI 1
#else
#define LO 1
#define HI 0
#endif

long odd_a, odd_lo, odd_hi, odd_b, odd_ret;

SEC("fentry/callee_odd")
int odd_entry(unsigned long long *ctx)
{
	odd_a = ctx[0];
	odd_lo = ctx[1 + LO];
	odd_hi = ctx[1 + HI];
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
	stack_lo = ctx[7 + LO];
	stack_hi = ctx[7 + HI];
	stack_i = ctx[9];
	return 0;
}

SEC("fexit/callee_stack")
int stack_exit(unsigned long long *ctx)
{
	stack_ret = ctx[10];
	return 0;
}

long split_e, split_lo, split_hi, split_i, split_ret;

SEC("fentry/callee_split")
int split_entry(unsigned long long *ctx)
{
	split_e = ctx[4];
	split_lo = ctx[5 + LO];
	split_hi = ctx[5 + HI];
	split_i = ctx[7];
	return 0;
}

SEC("fexit/callee_split")
int split_exit(unsigned long long *ctx)
{
	split_ret = ctx[8];
	return 0;
}

/* Refused: the trampoline would lose the stack argument. */
SEC("?fentry/callee_unreliable")
int unreliable_entry(unsigned long long *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
