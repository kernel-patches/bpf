// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define MIX_A	0xdeadbeefcafef00dULL
#define MIX_B	0x0123456789abcdefULL

typedef unsigned __int128 u128;

__noinline __u64 take_i128_global(int a, u128 v, int c)
{
	return (__u64)a + (__u64)(v >> 64) + (__u64)v + c;
}

SEC("tc")
__success __retval(0)
int aggregate_arg_int128_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v = ((u128)a << 64) | b;

	if (take_i128_global(1, v, 2) != a + b + 3)
		return 1;

	return 0;
}

char _license[] SEC("license") = "GPL";
