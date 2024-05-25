// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("check w reg equal if r reg upper32 bits 0")
__success
__naked void subreg_equality_1(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	*(u64 *)(r10 - 8) = r0;				\
	r2 = *(u32 *)(r10 - 8);				\
	/* At this point upper 4-bytes of r2 are 0,	\
	 * thus insn w3 = w2 should propagate reg id,	\
	 * and w2 < 9 comparison would also propagate	\
	 * the range for r3.				\
	 */						\
	w3 = w2;					\
	if w2 < 9 goto l0_%=;				\
	exit;						\
l0_%=:	if r3 < 9 goto l1_%=;				\
	/* r1 read is illegal at this point */		\
	r0 -= r1;					\
l1_%=:	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

SEC("socket")
__description("check w reg not equal if r reg upper32 bits not 0")
__failure __msg("R1 !read_ok")
__naked void subreg_equality_2(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	r2 = r0;					\
	/* Upper 4-bytes of r2 may not be 0, thus insn	\
	 * w3 = w2 should not propagate reg id,	and	\
	 * w2 < 9 comparison should not propagate	\
	 * the range for r3 either.			\
	 */						\
	w3 = w2;					\
	if w2 < 9 goto l0_%=;				\
	exit;						\
l0_%=:	if r3 < 9 goto l1_%=;				\
	/* r1 read is illegal at this point */		\
	r0 -= r1;					\
l1_%=:	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/*
 * The tests checks that the verifier doesn't WARN_ON in:
 * if (dst_reg->type == SCALAR_VALUE && dst_reg->id &&
 *     !WARN_ON_ONCE(dst_reg->id != other_dst_reg->id)) {
 */
SEC("socket")
__description("check this_branch_reg->id == other_branch_reg->id")
__success
__naked void reg_id(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	1:.byte 0xe5; /* may_goto */			\
	.byte 0;					\
	.long ((l0_%= - 1b - 8) / 8) & 0xffff;	\
	.short 0;					\
	r0 &= 1;					\
	r2 = r0;					\
	/* is_branch_taken will predict fallthrough */	\
	if r2 == 2 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
