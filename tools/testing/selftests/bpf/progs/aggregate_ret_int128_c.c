// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

#if __clang_major__ >= 23

typedef unsigned __int128 u128;

static __attribute__((noinline)) u128 make_i128(__u64 a, __u64 b)
{
	return ((u128)a << 64) | b;
}

SEC("tc")
int aggregate_ret_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xdeadbeefULL;
	u128 v;

	v = make_i128(a, b);
	if ((__u64)(v >> 64) != a)
		return 1;
	if ((__u64)v != b)
		return 2;

	v = bpf_kfunc_call_test_i128(a, b);
	if ((__u64)(v >> 64) != a)
		return 3;
	if ((__u64)v != b)
		return 4;

	return 0;
}

#else

SEC("tc")
int aggregate_ret_test(struct __sk_buff *skb)
{
	return -1;
}

#endif

char _license[] SEC("license") = "GPL";
