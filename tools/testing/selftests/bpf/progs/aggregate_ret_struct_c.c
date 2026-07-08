// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

#if __clang_major__ >= 23

struct pair {
	__u64 hi;
	__u64 lo;
};

static __attribute__((noinline)) struct pair make_pair(__u64 a, __u64 b)
{
	struct pair p = { .hi = a, .lo = b };

	return p;
}

SEC("tc")
int aggregate_ret_struct_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xdeadbeefULL;
	struct pair p;

	p = make_pair(a, b);
	if (p.hi != a)
		return 1;
	if (p.lo != b)
		return 2;

	return 0;
}

__attribute__((noinline)) struct pair make_pair_global(__u64 a, __u64 b)
{
	struct pair p = { .hi = a, .lo = b };

	return p;
}

SEC("tc")
int aggregate_ret_global_struct_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xcafef00dULL;
	struct pair p;

	p = make_pair_global(a, b);
	if (p.hi != a)
		return 1;
	if (p.lo != b)
		return 2;

	return 0;
}

SEC("tc")
int aggregate_ret_kfunc_struct_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xfeedfaceULL;
	struct bpf_kfunc_ret_ll p;

	p = bpf_kfunc_call_test_ret_ll(a, b);
	if (p.a != a)
		return 1;
	if (p.b != b)
		return 2;

	return 0;
}

#else

SEC("tc")
int aggregate_ret_struct_c_test(struct __sk_buff *skb)
{
	return -1;
}

SEC("tc")
int aggregate_ret_global_struct_c_test(struct __sk_buff *skb)
{
	return -1;
}

SEC("tc")
int aggregate_ret_kfunc_struct_c_test(struct __sk_buff *skb)
{
	return -1;
}

#endif

char _license[] SEC("license") = "GPL";
