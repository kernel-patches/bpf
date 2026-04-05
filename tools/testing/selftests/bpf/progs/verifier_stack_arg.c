// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, long long);
} map_hash_8b SEC(".maps");

#if defined(__TARGET_ARCH_x86) && defined(__BPF_FEATURE_STACK_ARGUMENT)

__noinline __used
static int subprog_6args(int a, int b, int c, int d, int e, int f)
{
	return a + b + c + d + e + f;
}

__noinline __used
static int subprog_7args(int a, int b, int c, int d, int e, int f, int g)
{
	return a + b + c + d + e + f + g;
}

SEC("tc")
__description("stack_arg: subprog with 6 args")
__success
__arch_x86_64
__naked void stack_arg_6args(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u64 *)(r12 - 8) = 6;"
		"call subprog_6args;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: two subprogs with >5 args")
__success
__arch_x86_64
__naked void stack_arg_two_subprogs(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u64 *)(r12 - 8) = 10;"
		"call subprog_6args;"
		"r6 = r0;"
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u64 *)(r12 - 16) = 30;"
		"*(u64 *)(r12 - 8) = 20;"
		"call subprog_7args;"
		"r0 += r6;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: read from uninitialized stack arg slot")
__failure
__arch_x86_64
__msg("invalid read from stack arg")
__naked void stack_arg_read_uninitialized(void)
{
	asm volatile (
		"r0 = *(u64 *)(r12 - 8);"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: gap at offset -8, only wrote -16")
__failure
__arch_x86_64
__msg("stack arg#6 not properly initialized")
__naked void stack_arg_gap_at_minus8(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u64 *)(r12 - 16) = 30;"
		"call subprog_7args;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: incorrect size of stack arg write")
__failure
__arch_x86_64
__msg("stack arg write must be 8 bytes, got 4")
__naked void stack_arg_not_written(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u32 *)(r12 - 8) = 30;"
		"call subprog_6args;"
		"exit;"
		::: __clobber_all
	);
}

__noinline __used
static long subprog_stack_arg_pruning_deref(int a, int b, int c, int d, int e, int f)
{
	long local = 0, *p, *ptr;

	if (a <= 3) {
		/* Overwrite the stack arg slot with a pointer to local */
		p = &local;
		asm volatile ("*(u64 *)(r12 - 8) = %[p];" :: [p] "r"(p) : "memory");
	}

	/* Read back the (possibly overwritten) stack arg slot */
	asm volatile ("%[ptr] = *(u64 *)(r12 - 8);" : [ptr] "=r"(ptr) :: "memory");

	/* Deref: safe for PTR_TO_STACK, unsafe for scalar */
	return *ptr;
}

SEC("tc")
__description("stack_arg: pruning with different stack arg types")
__failure
__flag(BPF_F_TEST_STATE_FREQ)
__arch_x86_64
__msg("invalid mem access 'scalar'")
__naked void stack_arg_pruning_type_mismatch(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"r1 = r0;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u64 *)(r12 - 8) = 42;"
		"call subprog_stack_arg_pruning_deref;"
		"exit;"
		:: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: release_reference invalidates stack arg slot")
__failure
__arch_x86_64
__msg("R0 invalid mem access 'scalar'")
__naked void stack_arg_release_ref(void)
{
	asm volatile (
		"r6 = r1;"
		/* struct bpf_sock_tuple tuple = {} */
		"r2 = 0;"
		"*(u32 *)(r10 - 8) = r2;"
		"*(u64 *)(r10 - 16) = r2;"
		"*(u64 *)(r10 - 24) = r2;"
		"*(u64 *)(r10 - 32) = r2;"
		"*(u64 *)(r10 - 40) = r2;"
		"*(u64 *)(r10 - 48) = r2;"
		/* sk = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple), 0, 0) */
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -48;"
		"r3 = %[sizeof_bpf_sock_tuple];"
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_sk_lookup_tcp];"
		/* r0 = sk (PTR_TO_SOCK_OR_NULL) */
		"if r0 == 0 goto l0_%=;"
		/* spill sk to stack arg slot */
		"*(u64 *)(r12 - 8) = r0;"
		/* release the reference */
		"r1 = r0;"
		"call %[bpf_sk_release];"
		/* r0 and stack arg slot (r12 - 8) should be invalid now. */
		"r0 = *(u64 *)(r12 - 8);"
		"r0 = *(u8 *)(r0 + 0);"
	"l0_%=:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_sk_lookup_tcp),
		  __imm(bpf_sk_release),
		  __imm_const(sizeof_bpf_sock_tuple, sizeof(struct bpf_sock_tuple))
		: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: pkt pointer in stack arg slot invalidated after pull_data")
__failure
__arch_x86_64
__msg("R0 invalid mem access 'scalar'")
__naked void stack_arg_stale_pkt_ptr(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = *(u32 *)(r6 + %[__sk_buff_data]);"
		"r8 = *(u32 *)(r6 + %[__sk_buff_data_end]);"
		/* check pkt has at least 1 byte */
		"r0 = r7;"
		"r0 += 1;"
		"if r0 > r8 goto l0_%=;"
		/* spill valid pkt pointer to stack arg slot */
		"*(u64 *)(r12 - 8) = r7;"
		/* bpf_skb_pull_data(skb, 0) — invalidates all pkt pointers */
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_skb_pull_data];"
		/* read back the stale pkt pointer from stack arg slot */
		"r0 = *(u64 *)(r12 - 8);"
		/* dereferencing stale pkt pointer should fail */
		"r0 = *(u8 *)(r0 + 0);"
	"l0_%=:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_skb_pull_data),
		  __imm_const(__sk_buff_data, offsetof(struct __sk_buff, data)),
		  __imm_const(__sk_buff_data_end, offsetof(struct __sk_buff, data_end))
		: __clobber_all
	);
}

SEC("tc")
__description("stack_arg: null propagation rejects deref on null branch")
__failure
__arch_x86_64
__msg("R1 invalid mem access 'scalar'")
__naked void stack_arg_null_propagation_fail(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		/* r0 = bpf_map_lookup_elem(&map_hash_8b, &key) */
		"r2 = r10;"
		"r2 += -8;"
		"r1 = %[map_hash_8b] ll;"
		"call %[bpf_map_lookup_elem];"
		/* spill PTR_TO_MAP_VALUE_OR_NULL to stack arg slot */
		"*(u64 *)(r12 - 8) = r0;"
		/* null check on r0 */
		"if r0 != 0 goto l0_%=;"
		/*
		 * on null branch, stack arg slot should be null (scalar 0).
		 * read it back and dereference should fail.
		 */
		"r1 = *(u64 *)(r12 - 8);"
		"r0 = *(u64 *)(r1 + 0);"
	"l0_%=:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm_addr(map_hash_8b)
		: __clobber_all
	);
}

#else

SEC("socket")
__description("stack_arg is not supported by compiler or jit, use a dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
