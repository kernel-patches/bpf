// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* Tests for the linear "base + step * k" description tracked per scalar register. */

#define __no_step __not_msg("step=") __msg("\n")

/*
 * Safe ALU64 arithmetic preserves a non-power-of-two stride and scales its base:
 * step=0+3 -> step=1+3 -> step=2+6 -> step=4+12.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 *= 3 {{.*}}step=0+3)")
__msg("r0 += 1 {{.*}}step=1+3)")
__msg("r0 *= 2 {{.*}}step=2+6)")
__msg("r0 <<= 1 {{.*}}step=4+12)")
__naked void step_arith64_no_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r0 *= 3;					\
	r0 += 1;					\
	r0 *= 2;					\
	r0 <<= 1;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Safe ALU32 multiplication and addition preserve the stride and scale its base:
 * step=0+3 -> step=1+3 -> step=2+6. MOV32 preserves the result.
 * LSH32 currently resets the stride, but must preserve the correct upper bound.
 */
SEC("socket")
__success __log_level(2)
__msg("w0 *= 3 {{.*}}step=0+3)")
__msg("w0 += 1 {{.*}}step=1+3)")
__msg("w0 *= 2 {{.*}}step=2+6)")
__msg("w1 = w0 {{.*}}step=2+6)")
__msg("w0 <<= 1 {{.*}}smax=umax=smax32=umax32=3064,") __no_step
__naked void step_arith32_no_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	w0 *= 3;					\
	w0 += 1;					\
	w0 *= 2;					\
	w1 = w0;					\
	w0 <<= 1;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Sign-crossing range with a non-power-of-2 step. After "*= 3; += -3" the value
 * set is {-3, 0, 3, 6}. The line description is tracked in signed space, so the
 * intersection keeps smax=6. A u64-modular intersection would mis-place the
 * line for the negative values and wrongly narrow smax to 4.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 += -3 {{.*}}smax=smax32=6)")
__naked void step_neg_value_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 3;					\
	r0 *= 3;					\
	r0 += -3;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * 0x49249249 * 7 wraps to U32_MAX. Keeping step=0+7 incorrectly caps the
 * result at 0xfffffffc instead of U32_MAX.
 * Adding 4 to {0xfffffffc, U32_MAX} wraps to {0, 3}; keeping step=1+3
 * incorrectly narrows the result to 1.
 * Shifting the same input left by 1 gives {0xfffffff8, 0xfffffffe};
 * keeping step=0+6 incorrectly narrows the result to 0xfffffffa.
 */
SEC("socket")
__success __log_level(2)
__msg("w0 *= 7 {{.*}}umax=0xffffffff,") __no_step
__msg("r2 = r0 {{.*}}R0=scalar({{.*}}step=0+3) R2=scalar({{.*}}step=0+3)")
__msg("w0 += 4 {{.*}}smax=umax=smax32=umax32=3,") __no_step
__msg("w2 <<= 1 {{.*}}smax=umax=umax32=0xfffffffe,") __no_step
__naked void step_arith32_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 *= 7;					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 1;					\
	r0 *= 3;					\
	r1 = 0xfffffffc ll;				\
	r0 += r1;					\
	r2 = r0;					\
	w0 += 4;					\
	w2 <<= 1;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Multiplying {0x2aaaaaaaaaaaaaab, 0x2aaaaaaaaaaaaaac} by 3 crosses S64_MAX
 * and gives {S64_MIN + 1, S64_MIN + 4}. Keeping step=0+3 excludes both.
 *
 * Adding 5 to {S64_MAX - 4, S64_MAX - 1} gives {S64_MIN, S64_MIN + 3}.
 * Updating the line to step=2+3 incorrectly narrows it to S64_MIN + 1.
 *
 * Adding -5 to {S64_MIN + 1, S64_MIN + 4} wraps to
 * {S64_MAX - 3, S64_MAX}. The stale base 0 modulo 3 excludes S64_MAX.
 *
 * Shifting {0x4000000000000008, 0x400000000000000b} left by 1 gives
 * {S64_MIN + 16, S64_MIN + 22}. Keeping step=0+6 excludes both.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 *= 3 {{.*}}smax=0x8000000000000004,") __no_step
__msg("r0 += r1 {{.*}}step=0+3)")
__msg("r0 += 5 {{.*}}smax=0x8000000000000003,") __no_step
__msg("r0 += r1 {{.*}}step=2+3)")
__msg("r0 += -5 {{.*}}umax=0x7fffffffffffffff,") __no_step
__msg("r0 += r1 {{.*}}step=0+3)")
__msg("r0 <<= 1 {{.*}}smax=0x8000000000000016,") __no_step
__naked void step_arith64_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 1;					\
	r2 = r0;					\
	r1 = 0x2aaaaaaaaaaaaaab ll;			\
	r0 += r1;					\
	r0 *= 3;					\
	r2 *= 3;					\
	r0 = r2;					\
	r1 = 0x7ffffffffffffffb ll;			\
	r0 += r1;					\
	r0 += 5;					\
	r0 = r2;					\
	r1 = 0x8000000000000001 ll;			\
	r0 += r1;					\
	r0 += -5;					\
	r0 = r2;					\
	r1 = 0x4000000000000008 ll;			\
	r0 += r1;					\
	r0 <<= 1;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * MOV32 maps {2^32, 2^32 + 3} to {0, 3}. The old base 1 modulo 3
 * excludes both results.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 += r1 {{.*}}step=1+3)")
__msg("w0 = w0 {{.*}}smax=umax=smax32=umax32=3,") __no_step
__naked void step_mov32_truncate(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 1;					\
	r0 *= 3;					\
	r1 = 0x100000000 ll;				\
	r0 += r1;					\
	w0 = w0;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * MOV32 maps {-4, -1} to {0xfffffffc, U32_MAX}. The old base 2
 * modulo 3 excludes U32_MAX.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 += -4 {{.*}}step=2+3)")
__msg("w0 = w0 {{.*}}umax=0xffffffff,") __no_step
__naked void step_mov32_negative(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 1;					\
	r0 *= 3;					\
	r0 += -4;					\
	w0 = w0;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Sign-extending {128, 131} from s8 gives {-128, -125}.
 * Keeping base 2 modulo 3 incorrectly narrows the result to -127.
 *
 * Sign-extending {32768, 32771} from s16 gives {-32768, -32765}.
 * Keeping base 2 modulo 3 incorrectly narrows the result to -32767.
 *
 * Sign-extending {2^31, 2^31 + 3} from s32 gives {S32_MIN, S32_MIN + 3}.
 * Keeping base 2 modulo 3 incorrectly narrows the result to S32_MIN + 1.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 += 128 {{.*}}step=2+3)")
__msg("r0 = (s8)r0 {{.*}}smax=smax32=-125,") __no_step
__msg("r0 += 32768 {{.*}}step=2+3)")
__msg("r0 = (s16)r0 {{.*}}smax=smax32=-32765,") __no_step
__msg("r0 += r1 {{.*}}step=2+3)")
__msg("r0 = (s32)r0 {{.*}}smax=0xffffffff80000003,") __no_step
__naked void step_movsx(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 1;					\
	r0 *= 3;					\
	r2 = r0;					\
	r0 += 128;					\
	r0 = (s8)r0;					\
	r0 = r2;					\
	r0 += 32768;					\
	r0 = (s16)r0;					\
	r0 = r2;					\
	r1 = 0x80000000 ll;				\
	r0 += r1;					\
	r0 = (s32)r0;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * R1 = R0 + 1 shares R0's scalar ID. Refining R0 to {0, 3, 6} must
 * translate its line as well as its bounds when updating R1 to {1, 4, 7}.
 * Copying R0's base 0 modulo 3 excludes the reachable value 7.
 */
SEC("socket")
__success __log_level(2)
__msg("r1 += 1 {{.*}}step=1+3)")
__msg("if r0 > 0x6 {{.*}}R1=scalar({{.*}}smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=7,{{.*}}step=1+3)")
__naked void step_linked_regs_add64(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 3;					\
	r0 *= 3;					\
	r1 = r0;					\
	r1 += 1;					\
	if r0 > 6 goto l_out_%=;			\
	r0 = r1;					\
l_out_%=:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
