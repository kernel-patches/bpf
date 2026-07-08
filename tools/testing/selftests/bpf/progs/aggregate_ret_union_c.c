// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#if __clang_major__ >= 23

union pair {
	__u64 halves[2];
	struct {
		__u64 lo;
		__u64 hi;
	} parts;
};

static __attribute__((noinline)) union pair make_pair(__u64 a, __u64 b)
{
	union pair p;

	p.parts.lo = a;
	p.parts.hi = b;
	return p;
}

SEC("tc")
int aggregate_ret_union_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xdeadbeefULL;
	union pair p;

	p = make_pair(a, b);
	if (p.parts.lo != a)
		return 1;
	if (p.parts.hi != b)
		return 2;

	return 0;
}

#else

SEC("tc")
int aggregate_ret_union_c_test(struct __sk_buff *skb)
{
	return -1;
}

#endif

char _license[] SEC("license") = "GPL";
