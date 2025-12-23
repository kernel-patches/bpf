// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <limits.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* This file contains unit tests for signed/unsigned division
 * operations, focusing on verifying whether BPF verifier's
 * tnum and interval analysis modules soundly and precisely
 * compute the results.
 */

SEC("socket")
__description("UDIV32, non-zero divisor")
__success __retval(0) __log_level(2)
__msg("w1 /= w2 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))")
__naked void udiv32_non_zero(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w2 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w2 &= 1;					\
	w2 |= 2;					\
	w1 /= w2;					\
	if w1 <= 4 goto l0_%=;				\
	/* Precise analysis will prune the path with error code */\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("UDIV32, zero divisor")
__success __retval(0) __log_level(2)
__msg("w1 /= w2 {{.*}}; R1=0 R2=0")
__naked void udiv32_zero_divisor(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w2 = 0;						\
	w1 /= w2;					\
	if w1 == 0 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("UDIV64, non-zero divisor")
__success __retval(0) __log_level(2)
__msg("r1 /= r2 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))")
__naked void udiv64_non_zero(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r2 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r2 &= 1;					\
	r2 |= 2;					\
	r1 /= r2;					\
	if r1 <= 4 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("UDIV64, zero divisor")
__success __retval(0) __log_level(2)
__msg("r1 /= r2 {{.*}}; R1=0 R2=0")
__naked void udiv64_zero_divisor(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r2 = 0;						\
	r1 /= r2;					\
	if r1 == 0 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV32, non-zero divisor")
__success __retval(0) __log_level(2)
__msg("w1 s/= w2 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))")
__naked void sdiv32_non_zero(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w2 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w2 &= 1;					\
	w2 |= 2;					\
	w1 s/= w2;					\
	if w1 s<= 4 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV32, non-zero divisor, negative dividend")
__success __retval(0) __log_level(2)
__msg("w1 s/= w2 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-4,smax32=0,var_off=(0x0; 0xffffffff))")
__naked void sdiv32_negative_dividend(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w2 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w1 = -w1;					\
	w2 &= 1;					\
	w2 |= 2;					\
	w1 s/= w2;					\
	if w1 s>= -4 goto l0_%=;			\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV32, non-zero divisor, negative divisor")
__success __retval(0) __log_level(2)
__msg("w1 s/= w2 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-4,smax32=0,var_off=(0x0; 0xffffffff))")
__naked void sdiv32_negative_divisor(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w2 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w2 &= 1;					\
	w2 |= 2;					\
	w2 = -w2;					\
	w1 s/= w2;					\
	if w1 s>= -4 goto l0_%=;			\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV32, non-zero divisor, both negative")
__success __retval(0) __log_level(2)
__msg("w1 s/= w2 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))")
__naked void sdiv32_both_negative(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w2 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w2 &= 1;					\
	w2 |= 2;					\
	w1 = -w1;					\
	w2 = -w2;					\
	w1 s/= w2;					\
	if w1 s<= 4 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV32, zero divisor")
__success __retval(0) __log_level(2)
__msg("w1 s/= w2 {{.*}}; R1=0 R2=0")
__naked void sdiv32_zero_divisor(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = w0;					\
	w1 &= 8;					\
	w1 |= 1;					\
	w2 = 0;						\
	w1 s/= w2;					\
	if w1 == 0 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV32, S32_MIN/-1")
__success __retval(0) __log_level(2)
__msg("w2 s/= -1 {{.*}}; R2=0x80000000")
__naked void sdiv32_overflow(void)
{
	asm volatile ("					\
	w1 = %[int_min];				\
	w2 = w1;					\
	w2 s/= -1;					\
	if w1 == w2 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm_const(int_min, INT_MIN)
	: __clobber_all);
}


SEC("socket")
__description("SDIV64, non-zero divisor")
__success __retval(0) __log_level(2)
__msg("r1 s/= r2 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))")
__naked void sdiv64_non_zero(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r2 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r2 &= 1;					\
	r2 |= 2;					\
	r1 s/= r2;					\
	if r1 s<= 4 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV64, non-zero divisor, negative dividend")
__success __retval(0) __log_level(2)
__msg("r1 s/= r2 {{.*}}; R1=scalar(smin=smin32=-4,smax=smax32=0)")
__naked void sdiv64_negative_dividend(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r2 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r1 = -r1;					\
	r2 &= 1;					\
	r2 |= 2;					\
	r1 s/= r2;					\
	if r1 s>= -4 goto l0_%=;			\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV64, non-zero divisor, negative divisor")
__success __retval(0) __log_level(2)
__msg("r1 s/= r2 {{.*}}; R1=scalar(smin=smin32=-4,smax=smax32=0)")
__naked void sdiv64_negative_divisor(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r2 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r2 &= 1;					\
	r2 |= 2;					\
	r2 = -r2;					\
	r1 s/= r2;					\
	if r1 s>= -4 goto l0_%=;			\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV64, non-zero divisor, both negative")
__success __retval(0) __log_level(2)
__msg("r1 s/= r2 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))")
__naked void sdiv64_both_negative(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r2 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r2 &= 1;					\
	r2 |= 2;					\
	r1 = -r1;					\
	r2 = -r2;					\
	r1 s/= r2;					\
	if r1 s<= 4 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV64, zero divisor")
__success __retval(0) __log_level(2)
__msg("r1 s/= r2 {{.*}}; R1=0 R2=0")
__naked void sdiv64_zero_divisor(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r1 &= 8;					\
	r1 |= 1;					\
	r2 = 0;						\
	r1 s/= r2;					\
	if r1 == 0 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("SDIV64, S64_MIN/-1")
__success __retval(0) __log_level(2)
__msg("r2 s/= -1 {{.*}}; R2=0x8000000000000000")
__naked void sdiv64_overflow(void)
{
	asm volatile ("					\
	r1 = %[llong_min] ll;				\
	r2 = r1;					\
	r2 s/= -1;					\
	if r1 == r2 goto l0_%=;				\
	r0 = *(u64 *)(r1 + 0);				\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm_const(llong_min, LLONG_MIN)
	: __clobber_all);
}