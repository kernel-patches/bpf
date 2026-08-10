// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

typedef unsigned __int128 u128;

/*
 * Reference kfunc addresses to force those BTF to be emitted. Taking the address
 * (rather than calling) avoids any dependence on the compiler lowering an __int128
 * or struct return value, which the BPF backend only supports from LLVM 23 on.
 */
void __kfunc_btf_root(void)
{
	asm volatile (""
	:
	: "r"(&bpf_kfunc_call_test_i128),
	  "r"(&bpf_kfunc_call_test_ret_pair),
	  "r"(&bpf_kfunc_call_test_ret_li),
	  "r"(&bpf_kfunc_call_test_ret_ii),
	  "r"(&bpf_kfunc_call_test_ret_uu));
}

#define I128_ASM_LO 0xABCDabcd12345678ULL
#define I128_ASM_HI 0x1234567890abcdefULL

static __naked __noinline u128 make_i128_asm(void)
{
	asm volatile (
	"r0 = %[lo] ll;"	/* low 64 bits */
	"r2 = %[hi] ll;"	/* high 64 bits */
	"exit;"
	:
	: __imm_const(lo, I128_ASM_LO), __imm_const(hi, I128_ASM_HI)
	);
}

SEC("tc")
int aggregate_ret_asm_test(struct __sk_buff *skb)
{
	__u64 lo, hi;

	asm volatile (
	"call %[callee];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: [callee]"i"(make_i128_asm)
	: "r0", "r1", "r2", "r3", "r4", "r5"
	);
	if (lo != I128_ASM_LO)
		return 1;
	if (hi != I128_ASM_HI)
		return 2;

	return 0;
}

/*
 * R0 holds bytes 0..7 of a kfunc return value and R2 bytes 8..15, so where a
 * member sits inside a register depends on the endianness of the target.
 * Although arm64 supports both little and big endian, for simplicity, only
 * do little endian for now..
 */
SEC("tc")
int aggregate_ret_asm_kfunc_test(struct __sk_buff *skb)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xdeadbeefULL;
	__u64 lo, hi;

	asm volatile (
	"r1 = %[a];"
	"r2 = %[b];"
	"call %[kfunc];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: [a]"r"(a), [b]"r"(b), [kfunc]"i"(bpf_kfunc_call_test_i128)
	: "r0", "r1", "r2", "r3", "r4", "r5"
	);
	if (hi != a + b)
		return 1;
	if (lo != a - b)
		return 2;
#endif

	return 0;
}

SEC("tc")
int aggregate_ret_struct_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xdeadbeefULL;
	__u64 lo, hi;

	/* struct { u64 hi; u64 lo; }: R0 = hi, R2 = lo. */
	asm volatile (
	"r1 = %[a];"
	"r2 = %[b];"
	"call %[kfunc];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: [a]"r"(a), [b]"r"(b), [kfunc]"i"(bpf_kfunc_call_test_ret_pair)
	: "r0", "r1", "r2", "r3", "r4", "r5"
	);
	if (lo != a + b)
		return 1;
	if (hi != a - b)
		return 2;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	/* struct { u64 a; int b; }: R0 = a, low 32 bits of R2 = b. */
	asm volatile (
	"r1 = %[a];"
	"r2 = %[b];"
	"call %[kfunc];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: [a]"r"(a), [b]"r"(b), [kfunc]"i"(bpf_kfunc_call_test_ret_li)
	: "r0", "r1", "r2", "r3", "r4", "r5"
	);
	if (lo != a)
		return 3;
	if ((int)hi != ~(int)b)
		return 4;

	/* struct { int a; int b; }: 8 bytes, packed into R0; R2 is not used. */
	asm volatile (
	"r1 = %[a];"
	"r2 = %[b];"
	"call %[kfunc];"
	"%[lo] = r0;"
	: [lo]"=r"(lo)
	: [a]"r"(a), [b]"r"(b), [kfunc]"i"(bpf_kfunc_call_test_ret_ii)
	: "r0", "r1", "r2", "r3", "r4", "r5"
	);
	if ((int)lo != (int)a)
		return 5;
	if ((int)(lo >> 32) != (int)b)
		return 6;
#endif

	return 0;
}

SEC("tc")
int aggregate_ret_union_test(struct __sk_buff *skb)
{
	__u64 a = skb->len;
	__u64 b = skb->len ^ 0xdeadbeefULL;
	__u64 lo, hi;

	asm volatile (
	"r1 = %[a];"
	"r2 = %[b];"
	"call %[kfunc];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: [a]"r"(a), [b]"r"(b), [kfunc]"i"(bpf_kfunc_call_test_ret_uu)
	: "r0", "r1", "r2", "r3", "r4", "r5"
	);
	if (lo != a + b)
		return 1;
	if (hi != a - b)
		return 2;

	return 0;
}

char _license[] SEC("license") = "GPL";
