// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "exceptions_cleanup.h"

static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_unwind_resume();
}

__u64 input = 0;
__u64 pads_ran = 0;
__u64 result = 0;

static __used __noinline __u64 foo3(__u64 x)
{
	bpf_preempt_disable();
	if (x > 100)
		asm volatile (
		"r1 = %[cookie];"
	"1:"	"call bpf_throw;"		/* cleanup region */
	"2:"
		"goto 3f;"
	"4:"					/* landing pad */
		"r7 = r0;"
		"call bpf_preempt_enable;"
		PAD_RAN("%[ran]")
		"r1 = r7;"
		"call bpf_unwind_resume;"
	"3:"
		CLEANUP_REC("1b", "2b", "4b")
		:
		: [cookie]"i"(THROW_COOKIE), [ran]"i"(RAN_FOO3_PREEMPT),
		  __imm_addr(pads_ran)
		: __clobber_all);
	bpf_preempt_enable();
	return x ^ 1;
}

__u64 never = 0;

static __used __naked __noinline void drop_glue(void)
{
	asm volatile (
	PAD_RAN("%[ran]")
	"exit;"
	:
	: [ran]"i"(RAN_FOO2_DROP), __imm_addr(pads_ran)
	: __clobber_all);
}

static __used __naked __noinline __u64 foo2(void)
{
	asm volatile (
	"r6 = r1;"
	"call bpf_rcu_read_lock;"
	"r1 = r6;"
"1:"	"call foo3;"			/* cleanup region #1 */
"2:"
	"r6 = r0;"
	"if r6 == 0 goto 5f;"
	"r1 = %[cookie];"
"3:"	"call bpf_throw;"		/* cleanup region #2 */
"4:"
	"r0 = 0;"
	"exit;"
"5:"
	"call bpf_rcu_read_unlock;"
	"r0 = r6;"
	"r0 += 1;"
	"exit;"
"6:"					/* landing pad, shared by both regions */
	"call drop_glue;"
	"call bpf_rcu_read_unlock;"
	PAD_RAN("%[ran_rcu]")
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "6b")
	CLEANUP_REC("3b", "4b", "6b")
	:
	: [cookie]"i"(THROW_COOKIE), [ran_rcu]"i"(RAN_FOO2_RCU),
	  __imm_addr(pads_ran)
	: __clobber_all);
}

static __used __naked __noinline void foo1v(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = %[input] ll;"
	"r1 = *(u64 *)(r1 + 0);"
"1:"	"call foo2;"			/* cleanup region */
"2:"
	"r6 = r0;"
	"call bpf_preempt_enable;"
	"r1 = %[result] ll;"
	"*(u64 *)(r1 + 0) = r6;"
	"goto 7f;"
"8:"					/* landing pad */
	"call bpf_preempt_enable;"
	PAD_RAN("%[ran]")
	"goto 9f;"
"7:"					/* the frame's own exit block */
	"r0 = 0;"
	"exit;"
"9:"					/* shared resume block */
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "8b")
	:
	: [ran]"i"(RAN_FOO1V_PREEMPT), __imm_addr(input),
	  __imm_addr(result), __imm_addr(pads_ran)
	: __clobber_all);
}

static __used __naked __noinline void bump(void)
{
	asm volatile (
	PAD_RAN("%[ran]")
	"r1 = %[never] ll;"
	"r1 = *(u64 *)(r1 + 0);"
	"if r1 == 0 goto 1f;"
	"r1 = 0;"
	"call bpf_throw;"
"1:"
	"exit;"				/* r0 deliberately left alone */
	:
	: [ran]"i"(RAN_BUMP), __imm_addr(never), __imm_addr(pads_ran)
	: __clobber_all);
}

__noinline __u64 foo1(void)
{
	bump();
	foo1v();
	return result;
}

SEC("syscall")
int entry(void *ctx)
{
	return foo1();
}

char _license[] SEC("license") = "GPL";
