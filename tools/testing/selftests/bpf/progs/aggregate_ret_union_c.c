// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#if defined(__clang_major__) && __clang_major__ >= 23

const volatile bool has_reg_pair_ret = true;

#define MIX_A	0xdeadbeefcafef00dULL
#define MIX_B	0x0123456789abcdefULL

union pair {
	__u64 halves[2];
	struct {
		__u64 lo;	/* R0 */
		__u64 hi;	/* R2 */
	} parts;
};

static __noinline union pair make_pair(__u64 a, __u64 b)
{
	union pair p;

	p.halves[0] = a + b;
	p.halves[1] = a - b;
	return p;
}

SEC("tc")
int aggregate_ret_union_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	union pair p;

	p = make_pair(a, b);
	if (p.parts.lo != a + b)
		return 1;
	if (p.parts.hi != a - b)
		return 2;

	return 0;
}

#else

const volatile bool has_reg_pair_ret = false;

SEC("tc")
int aggregate_ret_union_c_test(struct __sk_buff *skb)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
