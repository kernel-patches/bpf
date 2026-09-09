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
__load_if_JITed()
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
__load_if_JITed()
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

/*
 * arm64 rounds the register number up to an even one for an argument
 * aligned to 16 bytes, so it wants this __int128 in x2 and x3.
 * The x86-64 ABI has no such rule.
 */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_arg_kfunc_int128_odd(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v = ((u128)a << 64) | b;

	if (bpf_kfunc_call_test_i128_arg_odd(1, v, 2) != a + b + 3)
		return 1;

	return 0;
}

#if defined(__clang__) && defined(__BPF_FEATURE_STACK_ARGUMENT)

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
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

/*
 * The x86-64 ABI moves an argument its six remaining registers cannot hold
 * wholly onto the stack. arm64 , with eight argument registers, still has a
 * pair for it.
 */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
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

/* The same, with an argument after the struct to take the eighth register. */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_arg_kfunc_tail(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_pair_arg s = { .lo = a, .hi = b };

	if (bpf_kfunc_call_test_pair_arg_tail(1, 2, 3, 4, 5, s, 6) != a + b + 21)
		return 1;

	return 0;
}

/*
 * arm64 gives no register to an argument its eight registers cannot hold,
 * nor to anything after it. Past its six registers the x86-64 ABI has both
 * eightbytes on the stack either way.
 */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_arg_kfunc_split8(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_pair_arg s = { .lo = a, .hi = b };

	if (bpf_kfunc_call_test_pair_arg_split8(1, 2, 3, 4, 5, 6, 7, s) != a + b + 28)
		return 1;

	return 0;
}

/*
 * The same hole, with enough arguments after the __int128 that the shift
 * reaches the registers the BPF convention counts as stack slots: arm64
 * wants the last one in x6 where the BPF convention put it in x5.
 */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_arg_kfunc_int128_shift(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v = ((u128)a << 64) | b;

	if (bpf_kfunc_call_test_i128_arg_shift(1, v, 2, 3, 4) != a + b + 10)
		return 1;

	return 0;
}

/*
 * One argument further and the hole pushes the last one off x7 and onto the
 * arm64 stack, which the JIT does not shift into. The x86-64 ABI packs the
 * eightbytes, so its last two are on the stack where BPF put them.
 */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_arg_kfunc_int128_ovf(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v = ((u128)a << 64) | b;

	if (bpf_kfunc_call_test_i128_arg_ovf(1, v, 2, 3, 4, 5, 6) != a + b + 21)
		return 1;

	return 0;
}

/*
 * Both conventions pad the stack to align this __int128, and the BPF
 * convention pads for neither, so both JITs move it up an eightbyte.
 */
SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_arg_kfunc_int128_pad(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v = ((u128)a << 64) | b;

	if (bpf_kfunc_call_test_i128_arg_pad(1, 2, 3, 4, 5, 6, 7, v) != a + b + 28)
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
