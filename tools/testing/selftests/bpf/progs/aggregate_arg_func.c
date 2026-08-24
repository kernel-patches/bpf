// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

typedef unsigned __int128 u128;

struct pair {
	__u64 lo;	/* first argument register */
	__u64 hi;	/* second argument register */
};

struct too_big {
	__u64 a;
	__u64 b;
	__u64 c;
};

/*
 * The callers below are written in assembly so that the argument registers are
 * spelled out in the test rather than chosen by the compiler, and so that a
 * prototype the compiler refuses to lower at a call site, such as a struct too
 * large to pass by value, can still be handed to the verifier. The callees stay
 * in C: a naked function records its parameters in BTF without names, which the
 * kernel rejects, taking the rest of the BTF with it.
 */

/*
 * GCC passes an aggregate by invisible reference, so a callee it compiles
 * expects a pointer where BTF says the two halves of the struct are, and the
 * tests below, which hand it those halves, do not apply.
 */
#if defined(__clang__)

__noinline __u64 global_arg_pair(int a, struct pair p, int c)
{
	return (__u64)a + p.lo + p.hi + c;
}

SEC("tc")
__success __retval(0x33)
__naked int aggregate_arg_pair_asm(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = 0x10;"	/* p.lo */
	"r3 = 0x20;"	/* p.hi */
	"r4 = 2;"
	"call %[global_arg_pair];"
	"exit;"
	:
	: __imm(global_arg_pair)
	: __clobber_all);
}

/*
 * Both halves of the struct are ordinary scalar arguments, so a pointer in
 * either is refused at the call site rather than reaching the callee as an
 * opaque scalar.
 */
SEC("tc")
__failure __msg("R2 is not a scalar")
__naked int aggregate_arg_pair_ptr_fail(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = r10;"	/* a stack pointer where p.lo belongs */
	"r3 = 0x20;"
	"r4 = 2;"
	"call %[global_arg_pair];"
	"exit;"
	:
	: __imm(global_arg_pair)
	: __clobber_all);
}

#endif

__noinline __u64 global_arg_too_big(struct too_big s)
{
	return s.a + s.b + s.c;
}

SEC("tc")
__failure __msg("in global_arg_too_big() has size 24, only 1 to 16 bytes can be passed by value")
__naked int aggregate_arg_too_big_fail(void)
{
	asm volatile (
	"r1 = 0;"
	"r2 = 0;"
	"r3 = 0;"
	"call %[global_arg_too_big];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_arg_too_big)
	: __clobber_all);
}

/*
 * The callees below take more than the five argument slots the BPF calling
 * convention keeps in registers, which the compiler can only lower once it
 * supports stack arguments.
 */
#if defined(__BPF_FEATURE_STACK_ARGUMENT)

/*
 * A global function has no stack arguments, so a struct that would start in the
 * last argument register and run onto the stack is out of room.
 */
__noinline __u64 global_arg_split(int a, int b, int c, int d, struct pair p)
{
	return (__u64)a + b + c + d + p.lo + p.hi;
}

SEC("tc")
__failure __msg("global function global_arg_split() needs 6 > 5 argument slots")
__naked int aggregate_arg_split_fail(void)
{
	asm volatile (
	"r1 = 0;"
	"r2 = 0;"
	"r3 = 0;"
	"r4 = 0;"
	"r5 = 0;"
	"call %[global_arg_split];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_arg_split)
	: __clobber_all);
}

/* The same, with the argument registers used up before the last struct. */
__noinline __u64 global_arg_past_regs(struct pair p, struct pair q, int a, struct pair r)
{
	return p.lo + p.hi + q.lo + q.hi + a + r.lo + r.hi;
}

SEC("tc")
__failure __msg("global function global_arg_past_regs() needs 7 > 5 argument slots")
__naked int aggregate_arg_past_regs_fail(void)
{
	asm volatile (
	"r1 = 0;"
	"r2 = 0;"
	"r3 = 0;"
	"r4 = 0;"
	"r5 = 0;"
	"call %[global_arg_past_regs];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_arg_past_regs)
	: __clobber_all);
}

/*
 * Five parameters, but the __int128 takes two registers, so the last parameter
 * would be a stack argument, which a global function cannot have.
 */
__noinline __u64 global_arg_i128_slots(u128 v, int a, int b, int c, int d)
{
	return (__u64)v + a + b + c + d;
}

SEC("tc")
__failure __msg("global function global_arg_i128_slots() needs 6 > 5 argument slots")
__naked int aggregate_arg_i128_slots_fail(void)
{
	asm volatile (
	"r1 = 0;"
	"r2 = 0;"
	"r3 = 0;"
	"r4 = 0;"
	"r5 = 0;"
	"call %[global_arg_i128_slots];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_arg_i128_slots)
	: __clobber_all);
}

#endif

char _license[] SEC("license") = "GPL";
