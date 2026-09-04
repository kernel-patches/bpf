// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"
#include "bpf_misc.h"

typedef unsigned __int128 u128;

#define MIX_A	0xdeadbeefcafef00dULL
#define MIX_B	0x0123456789abcdefULL

#if defined(__clang__)

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(0)
int aggregate_arg_kfunc_struct(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_pair_arg s = { .lo = a, .hi = b };

	if (bpf_kfunc_call_test_pair_arg(1, s, 2) != a + b + 3)
		return 1;

	return 0;
}

#endif

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(0)
int aggregate_arg_kfunc_int128(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v = ((u128)a << 64) | b;

	if (bpf_kfunc_call_test_i128_arg(1, 2, v) != a + b + 3)
		return 1;

	return 0;
}

#if defined(__clang__) && defined(__BPF_FEATURE_STACK_ARGUMENT)

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(0)
int aggregate_arg_kfunc_last_regs(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_pair_arg s = { .lo = a, .hi = b };

	if (bpf_kfunc_call_test_pair_arg_nofit(1, 2, 3, 4, s) != a + b + 10)
		return 1;

	return 0;
}

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(0)
int aggregate_arg_kfunc_straddle(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_big_arg s = { .a = a, .b = b };

	if (bpf_kfunc_call_stack_arg_big(1, 2, 3, 4, 5, s) != a + b + 15)
		return 1;

	return 0;
}

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(0)
int aggregate_arg_kfunc_disorder(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_pair_arg s = { .lo = a, .hi = b };

	if (bpf_kfunc_call_test_pair_arg_disorder(1, 2, 3, 4, 5, s, 6) != a + b + 21)
		return 1;

	return 0;
}

#endif

SEC("tc")
__arch_x86_64 __arch_arm64
__failure __msg("R1 type STRUCT is not composed of scalars")
int aggregate_arg_kfunc_ptr_member(struct __sk_buff *skb)
{
	struct prog_test_ptr_arg s = { .p = skb, .x = 1 };

	return bpf_kfunc_call_test_ptr_arg(s);
}

char _license[] SEC("license") = "GPL";
