// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("scalars: find linked scalars")
__failure
__msg("math between fp pointer and 2147483647 is not allowed")
__naked void scalars(void)
{
	asm volatile ("				\
	r0 = 0;					\
	r1 = 0x80000001 ll;			\
	r1 /= 1;				\
	r2 = r1;				\
	r4 = r1;				\
	w2 += 0x7FFFFFFF;			\
	w4 += 0;				\
	if r2 == 0 goto l1;			\
	exit;					\
l1:						\
	r4 >>= 63;				\
	r3 = 1;					\
	r3 -= r4;				\
	r3 *= 0x7FFFFFFF;			\
	r3 += r10;				\
	*(u8*)(r3 - 1) = r0;			\
	exit;					\
"	::: __clobber_all);
}

SEC("socket")
__description("scalars: linked scalars with negative offset")
__success
__naked void scalars_neg(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += -4;					\
	if r1 s< 0 goto l2;				\
	if r0 != 0 goto l2;				\
	r0 /= 0;					\
l2:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Same test but using BPF_SUB instead of BPF_ADD with negative immediate */
SEC("socket")
__description("scalars: linked scalars with SUB")
__success
__naked void scalars_neg_sub(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 -= 4;					\
	if r1 s< 0 goto l2_sub;				\
	if r0 != 0 goto l2_sub;				\
	r0 /= 0;					\
l2_sub:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 32-bit ALU: linked scalar tracking not supported, ID cleared */
SEC("socket")
__description("scalars: linked scalars 32-bit ADD not tracked")
__failure
__msg("div by zero")
__naked void scalars_neg_alu32_add(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 += -4;					\
	if w1 s< 0 goto l2_alu32_add;			\
	if w0 != 0 goto l2_alu32_add;			\
	r0 /= 0;					\
l2_alu32_add:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 32-bit ALU: linked scalar tracking not supported, ID cleared */
SEC("socket")
__description("scalars: linked scalars 32-bit SUB not tracked")
__failure
__msg("div by zero")
__naked void scalars_neg_alu32_sub(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 -= 4;					\
	if w1 s< 0 goto l2_alu32_sub;			\
	if w0 != 0 goto l2_alu32_sub;			\
	r0 /= 0;					\
l2_alu32_sub:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Positive offset: r1 = r0 + 4, then if r1 >= 6, r0 >= 2, so r0 != 0 */
SEC("socket")
__description("scalars: linked scalars positive offset")
__success
__naked void scalars_pos(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += 4;					\
	if r1 < 6 goto l2_pos;				\
	if r0 != 0 goto l2_pos;				\
	r0 /= 0;					\
l2_pos:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* SUB with negative immediate: r1 -= -4 is equivalent to r1 += 4 */
SEC("socket")
__description("scalars: linked scalars SUB negative immediate")
__success
__naked void scalars_sub_neg_imm(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 -= -4;					\
	if r1 < 6 goto l2_sub_neg;			\
	if r0 != 0 goto l2_sub_neg;			\
	r0 /= 0;					\
l2_sub_neg:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Double ADD clears the ID (can't accumulate offsets) */
SEC("socket")
__description("scalars: linked scalars double ADD clears ID")
__failure
__msg("div by zero")
__naked void scalars_double_add(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += 2;					\
	r1 += 2;					\
	if r1 < 6 goto l2_double;			\
	if r0 != 0 goto l2_double;			\
	r0 /= 0;					\
l2_double:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that sync_linked_regs() correctly handles large offset differences.
 * r1.off = S32_MIN, r2.off = 1, delta = S32_MIN - 1 requires 64-bit math.
 */
SEC("socket")
__description("scalars: linked regs sync with large delta (S32_MIN offset)")
__success
__naked void scalars_sync_delta_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r2 = r0;					\
	r1 += %[s32_min];				\
	r2 += 1;					\
	if r2 s< 100 goto l2_overflow;			\
	if r1 s< 0 goto l2_overflow;			\
	r0 /= 0;					\
l2_overflow:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  [s32_min]"i"((int)(-2147483647 - 1))
	: __clobber_all);
}

/*
 * Another large delta case: r1.off = S32_MAX, r2.off = -1.
 * delta = S32_MAX - (-1) = S32_MAX + 1 requires 64-bit math.
 */
SEC("socket")
__description("scalars: linked regs sync with large delta (S32_MAX offset)")
__success
__naked void scalars_sync_delta_overflow_large_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r2 = r0;					\
	r1 += %[s32_max];				\
	r2 += -1;					\
	if r2 s< 0 goto l2_large;			\
	if r1 s>= 0 goto l2_large;			\
	r0 /= 0;					\
l2_large:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  [s32_max]"i"((int)2147483647)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
