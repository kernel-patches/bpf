// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

typedef unsigned __int128 u128;

__naked u128 global_agg_good(void)
{
	asm volatile (
	"r0 = 0x1234;"	/* low 64 bits */
	"r2 = 0x5678;"	/* high 64 bits */
	"exit;"
	);
}

__naked u128 global_agg_bad(void)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	);
}

__naked u128 global_agg_bad_ptr(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = r10;"
	"exit;"
	);
}

SEC("tc")
__success __retval(0)
int aggregate_ret_global(void *ctx)
{
	__u64 lo, hi;

	asm volatile (
	"call %[global_agg_good];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: __imm(global_agg_good)
	: "r0", "r1", "r2", "r3", "r4", "r5");
	if (lo != 0x1234)
		return 1;
	if (hi != 0x5678)
		return 2;
	return 0;
}

SEC("tc")
__failure __msg("R2 !read_ok")
__naked int aggregate_ret_global_fail(void)
{
	asm volatile (
	"call %[global_agg_bad];"
	"r0 = r2;"
	"exit;"
	:
	: __imm(global_agg_bad)
	: __clobber_all);
}

SEC("tc")
__failure __msg("At subprogram exit the register R2 is not a scalar value")
__naked int aggregate_ret_global_ptr_fail(void)
{
	asm volatile (
	"call %[global_agg_bad_ptr];"
	"r0 = r2;"
	"exit;"
	:
	: __imm(global_agg_bad_ptr)
	: __clobber_all);
}

static __naked __noinline u128 static_agg_bad_ptr(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = r10;"	/* stack pointer placed in the second return register */
	"exit;"
	);
}

/*
 * R2 is caller-saved and only copied from the callee at exit; a PTR_TO_STACK
 * left in it is turned into an uninitialized R2 in the caller. A caller that
 * never reads R2 is therefore unaffected and loads fine.
 */
SEC("tc")
__success __retval(0)
__naked int aggregate_ret_static_ptr_unused(void)
{
	asm volatile (
	"call %[static_agg_bad_ptr];"
	"r0 = 0;"		/* R2 holds a stack pointer but is never read */
	"exit;"
	:
	: __imm(static_agg_bad_ptr)
	: __clobber_all);
}

/* But a caller that does read the returned stack pointer is rejected. */
SEC("tc")
__failure __msg("R2 !read_ok")
__naked int aggregate_ret_static_ptr_read_fail(void)
{
	asm volatile (
	"call %[static_agg_bad_ptr];"
	"r0 = r2;"		/* using the returned stack pointer is rejected */
	"exit;"
	:
	: __imm(static_agg_bad_ptr)
	: __clobber_all);
}

static __naked __noinline u128 static_agg_no_r2(void)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	);
}

SEC("tc")
__failure __msg("R2 !read_ok")
__naked int aggregate_ret_static_uninit_fail(void)
{
	asm volatile (
	"call %[static_agg_no_r2];"
	"r0 = r2;"
	"exit;"
	:
	: __imm(static_agg_no_r2)
	: __clobber_all);
}

static __naked __noinline u128 static_agg_precise(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = 4;"	/* second half; its value is made precise below */
	"exit;"
	);
}

SEC("tc")
__success __retval(0)
__log_level(2)
__msg("mark_precise: frame0: last_idx 5 first_idx 0 subseq_idx -1")
__msg("mark_precise: frame0: regs=r6 stack= before 4: (07) r1 += -8")
__msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r6 stack= before 2: (57) r6 &= 7")
__msg("mark_precise: frame0: regs=r6 stack= before 1: (bf) r6 = r2")
__msg("mark_precise: frame0: regs=r2 stack= before 12: (95) exit")
__msg("mark_precise: frame1: regs=r2 stack= before 11: (b7) r2 = 4")
__naked int aggregate_ret_static_precise(void)
{
	asm volatile (
	"call %[static_agg_precise];"
	"r6 = r2;"		/* derived from the aggregate's second half */
	"r6 &= 7;"		/* keep it in [0, 7] to index the stack */
	"r1 = r10;"
	"r1 += -8;"
	"r1 += r6;"		/* ptr += scalar marks r6 (hence R2) precise */
	"r0 = 0;"
	"*(u8 *)(r1 + 0) = r0;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(static_agg_precise)
	: __clobber_all);
}

SEC("tc")
__success __retval(0)
__log_level(2)
__msg("mark_precise: frame0: last_idx 5 first_idx 0 subseq_idx -1")
__msg("mark_precise: frame0: regs=r6 stack= before 4: (07) r1 += -8")
__msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r6 stack= before 2: (57) r6 &= 7")
__msg("mark_precise: frame0: regs=r6 stack= before 1: (bf) r6 = r2")
__msg("mark_precise: frame0: regs=r2 stack= before 0: (85) call pc+9")
__naked int aggregate_ret_global_precise(void)
{
	asm volatile (
	"call %[global_agg_good];"
	"r6 = r2;"		/* derived from the aggregate's second half */
	"r6 &= 7;"		/* keep it in [0, 7] to index the stack */
	"r1 = r10;"
	"r1 += -8;"
	"r1 += r6;"		/* ptr += scalar marks r6 (hence R2) precise */
	"r0 = 0;"
	"*(u8 *)(r1 + 0) = r0;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_agg_good)
	: __clobber_all);
}

SEC("tc")
__failure __msg("return value larger than 8 bytes is not supported at program exit")
__naked u128 aggregate_ret_entry_fail(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = 0;"
	"exit;"
	);
}

#if __clang_major__ >= 23

struct pair {
	__u64 hi;
	__u64 lo;
};

union upair {
	__u64 halves[2];
	struct {
		__u64 lo;
		__u64 hi;
	} parts;
};

/* A by-value struct that smuggles a pointer, which must be rejected. */
struct with_ptr {
	void *p;
	__u64 x;
};

/* A by-value union that smuggles a pointer, which must be rejected too. */
union upair_with_ptr {
	void *p;
	__u64 halves[2];
};

/* Global subprogram returning a scalar-only 16-byte struct in R0:R2. */
__naked struct pair global_ret_struct(void)
{
	asm volatile (
	"r0 = 0x1234;"	/* struct's first half */
	"r2 = 0x5678;"	/* struct's second half */
	"exit;"
	);
}

/* Global subprogram returning a scalar-only 16-byte union in R0:R2. */
__naked union upair global_ret_union(void)
{
	asm volatile (
	"r0 = 0x1234;"
	"r2 = 0x5678;"
	"exit;"
	);
}

SEC("tc")
__success __retval(0)
int aggregate_ret_global_struct(void *ctx)
{
	__u64 lo, hi;

	asm volatile (
	"call %[global_ret_struct];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: __imm(global_ret_struct)
	: "r0", "r1", "r2", "r3", "r4", "r5");
	if (lo != 0x1234)
		return 1;
	if (hi != 0x5678)
		return 2;
	return 0;
}

SEC("tc")
__success __retval(0)
int aggregate_ret_global_union(void *ctx)
{
	__u64 lo, hi;

	asm volatile (
	"call %[global_ret_union];"
	"%[lo] = r0;"
	"%[hi] = r2;"
	: [lo]"=r"(lo), [hi]"=r"(hi)
	: __imm(global_ret_union)
	: "r0", "r1", "r2", "r3", "r4", "r5");
	if (lo != 0x1234)
		return 1;
	if (hi != 0x5678)
		return 2;
	return 0;
}

__naked struct with_ptr global_ret_struct_ptr(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = 0;"
	"exit;"
	);
}

SEC("tc")
__failure __msg("Global function global_ret_struct_ptr() has unsupported return type")
__naked int aggregate_ret_global_struct_ptr_fail(void)
{
	asm volatile (
	"call %[global_ret_struct_ptr];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_ret_struct_ptr)
	: __clobber_all);
}

__naked union upair_with_ptr global_ret_union_ptr(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = 0;"
	"exit;"
	);
}

SEC("tc")
__failure __msg("Global function global_ret_union_ptr() has unsupported return type")
__naked int aggregate_ret_global_union_ptr_fail(void)
{
	asm volatile (
	"call %[global_ret_union_ptr];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(global_ret_union_ptr)
	: __clobber_all);
}

#endif /* __clang_major__ >= 23 */

static __naked u128 agg_callee(void)
{
	asm volatile (
	"r0 = 1;"
	"r2 = 2;"
	"exit;"
	);
}

SEC("tc")
__log_level(2)
__msg("Live regs before insn:")
/*
 * R2 is read at the exit of agg_callee() (insn 5), which returns a pair, but
 * not at the exit of this program (insn 2), which returns an int.
 */
__msg("0: .12345.... (85) call pc+2")
__msg("1: ..2....... (bf) r0 = r2")
__msg("2: 0......... (95) exit")
__msg("3: .......... (b7) r0 = 1")
__msg("4: 0......... (b7) r2 = 2")
__msg("5: 0.2....... (95) exit")
__naked int aggregate_ret_live(void)
{
	asm volatile (
	"call %[agg_callee];"
	"r0 = r2;"
	"exit;"
	:
	: [agg_callee]"i"(agg_callee)
	: __clobber_all);
}

/*
 * A static subprogram is verified inline, so prepare_func_exit() hands the
 * caller the callee's actual R0:R2 register state rather than an opaque scalar
 * pair. A pointer in the returned struct therefore stays tracked and is usable
 * by the caller, which is why btf_validate_return_type() does not apply the
 * scalar-only restriction to a local function. Return the context pointer as
 * the upper half and dereference it in the caller.
 */
struct ptr_pair {
	void *p;
	__u64 x;
};

static __naked __noinline struct ptr_pair static_ret_ptr_pair(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = r1;"
	"exit;"
	);
}

SEC("tc")
__success __retval(0)
__naked int aggregate_ret_static_ptr_pair(void)
{
	asm volatile (
	"call %[static_ret_ptr_pair];"
	"r1 = *(u32 *)(r2 + 0);"	/* deref the returned ctx pointer */
	"r0 = 0;"
	"exit;"
	:
	: __imm(static_ret_ptr_pair)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
