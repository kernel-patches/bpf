// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

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
__description("stack_arg: gap at offset -8, only wrote -16")
__failure
__msg("stack arg#6 not properly initialized")
__arch_x86_64
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
__description("stack_arg: misaligned stack arg write")
__failure
__msg("stack arg write must be 8 bytes, got 4")
__arch_x86_64
__naked void stack_arg_not_written(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"*(u32 *)(r12 - 4) = 30;"
		"call subprog_6args;"
		"exit;"
		::: __clobber_all
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
