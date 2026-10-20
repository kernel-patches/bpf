// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* Unknown to the verifier, zero at run time. */
__u32 zero;

SEC("socket")
__description("branch invert: condition true at run time")
__success __retval(1)
__xlated("3: if r0 != 0x0 goto pc+2")
__xlated("4: r0 = 1")
__naked void invert_taken(void)
{
	asm volatile ("					\
	r1 = %[zero] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	if r0 == 0 goto l0_%=;				\
	goto l1_%=;					\
l0_%=:	r0 = 1;						\
	exit;						\
l1_%=:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(zero)
	: __clobber_all);
}

SEC("socket")
__description("branch invert: condition false at run time")
__success __retval(2)
__xlated("3: if r0 == 0x0 goto pc+2")
__xlated("4: r0 = 1")
__naked void invert_not_taken(void)
{
	asm volatile ("					\
	r1 = %[zero] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	if r0 != 0 goto l0_%=;				\
	goto l1_%=;					\
l0_%=:	r0 = 1;						\
	exit;						\
l1_%=:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(zero)
	: __clobber_all);
}

SEC("socket")
__description("branch invert: loop latch")
__success __retval(45)
__xlated("4: if r1 != 0xa goto pc-3")
__xlated("5: exit")
__naked void invert_loop_latch(void)
{
	asm volatile ("					\
	r0 = 0;						\
	r1 = 0;						\
l0_%=:	r0 += r1;					\
	r1 += 1;					\
	if r1 == 10 goto l1_%=;				\
	goto l0_%=;					\
l1_%=:	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("branch invert: 32-bit comparison")
__success __retval(1)
__xlated("3: if w0 >= 0x7 goto pc+2")
__xlated("4: r0 = 1")
__naked void invert_jmp32(void)
{
	asm volatile ("					\
	r1 = %[zero] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	if w0 < 7 goto l0_%=;				\
	goto l1_%=;					\
l0_%=:	r0 = 1;						\
	exit;						\
l1_%=:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(zero)
	: __clobber_all);
}

SEC("socket")
__description("branch invert: skip when the goto is a jump target")
__success __retval(1)
__xlated("4: if r0 == 0x0 goto pc+1")
__xlated("5: goto pc+2")
__naked void no_invert_jump_target(void)
{
	asm volatile ("					\
	r1 = %[zero] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	if r0 > 5 goto l0_%=;				\
	if r0 == 0 goto l1_%=;				\
l0_%=:	goto l2_%=;					\
l1_%=:	r0 = 1;						\
	exit;						\
l2_%=:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(zero)
	: __clobber_all);
}

SEC("socket")
__description("branch invert: skip JSET, it has no inverse")
__success __retval(2)
__xlated("3: if r0 & 0x1 goto pc+1")
__xlated("4: goto pc+2")
__naked void no_invert_jset(void)
{
	asm volatile ("					\
	r1 = %[zero] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	if r0 & 1 goto l0_%=;				\
	goto l1_%=;					\
l0_%=:	r0 = 1;						\
	exit;						\
l1_%=:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(zero)
	: __clobber_all);
}

#ifdef CAN_USE_GOTOL

SEC("socket")
__description("branch invert: skip gotol")
__success __retval(1)
__xlated("3: if r0 == 0x0 goto pc+1")
__xlated("4: gotol pc+2")
__naked void no_invert_gotol(void)
{
	asm volatile ("					\
	r1 = %[zero] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	if r0 == 0 goto l0_%=;				\
	gotol l1_%=;					\
l0_%=:	r0 = 1;						\
	exit;						\
l1_%=:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(zero)
	: __clobber_all);
}

#endif

char _license[] SEC("license") = "GPL";
