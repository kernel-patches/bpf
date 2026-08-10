// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#if defined(__clang_major__) && __clang_major__ >= 23

const volatile bool has_reg_pair_ret = true;

#define MIX_A	0xdeadbeefcafef00dULL
#define MIX_B	0x0123456789abcdefULL

typedef unsigned __int128 u128;

static __noinline u128 make_i128(__u64 a, __u64 b)
{
	return ((u128)(a + b) << 64) | (a - b);
}

SEC("tc")
int aggregate_ret_int128_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v;

	v = make_i128(a, b);
	if ((__u64)(v >> 64) != a + b)
		return 1;
	if ((__u64)v != a - b)
		return 2;

	return 0;
}

#else

const volatile bool has_reg_pair_ret = false;

SEC("tc")
int aggregate_ret_int128_c_test(struct __sk_buff *skb)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
