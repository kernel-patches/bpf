// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"
#include "bpf_misc.h"

#if defined(__clang_major__) && __clang_major__ >= 23

#define MIX_A	0xdeadbeefcafef00dULL
#define MIX_B	0x0123456789abcdefULL

typedef unsigned __int128 u128;

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_ret_kfunc_int128_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	u128 v;

	v = bpf_kfunc_call_test_i128(a, b);
	if ((__u64)(v >> 64) != a + b)
		return 1;
	if ((__u64)v != a - b)
		return 2;

	return 0;
}

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
int aggregate_ret_kfunc_struct_c_test(struct __sk_buff *skb)
{
	__u64 a = skb->len ^ MIX_A;
	__u64 b = skb->len ^ MIX_B;
	struct prog_test_ret_pair p;

	p = bpf_kfunc_call_test_ret_pair(a, b);
	if (p.hi != a + b)
		return 1;
	if (p.lo != a - b)
		return 2;

	return 0;
}

#else

SEC("socket")
__description("aggregate_ret_kfunc_c: needs LLVM 23, dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
