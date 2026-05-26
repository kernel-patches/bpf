// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("tracepoint")
__failure
__log_level(1)
__msg("two_level_calls():")
__msg("  0: (85) call pc+1")
__msg("  1: (95) exit")
__msg("two_level_calls__l1():")
__msg("  2: (85) call pc+1")
__msg("  3: (95) exit")
__msg("two_level_calls__l2():")
__msg("  4: (b7) r0 = 0")
__msg("  5: (07) r0 += 1")
__msg("  6: (05) goto pc-2")
__msg("#1 most visited simulated stacktrace (visited 499999 times):")
__msg("  two_level_calls/0 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("  two_level_calls__l1/2 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("  two_level_calls__l2/5 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("BPF program is too large. Processed 1000001 insn")
__naked void two_level_calls(void)
{
	asm volatile ("					\
	call two_level_calls__l1;		\
	exit;						\
"	::: __clobber_all);
}

__used
static __naked void two_level_calls__l1(void)
{
	asm volatile ("					\
	call two_level_calls__l2;		\
	exit;						\
"	::: __clobber_all);
}

__used
static __naked void two_level_calls__l2(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	goto 1b;					\
"	::: __clobber_all);
}

SEC("tracepoint")
__failure
__log_level(1)
__msg("two_loops():")
__msg("  0: (b7) r6 = 250000")
__msg("  1: (b7) r0 = 0")
__msg("  2: (07) r0 += 1")
__msg("  3: (ad) if r0 < r6 goto pc-2")
__msg("  4: (b7) r0 = 0")
__msg("  5: (07) r0 += 1")
__msg("  6: (05) goto pc-2")
__msg("#1 most visited simulated stacktrace (visited 250000 times):")
__msg("  two_loops/2 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("#2 most visited simulated stacktrace (visited 249999 times):")
__msg("  two_loops/5 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("BPF program is too large")
__naked void two_loops(void)
{
	asm volatile ("					\
	r6 = 250000;					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 < r6 goto 1b;				\
	r0 = 0;						\
2:	r0 += 1;					\
	goto 2b;					\
"	::: __clobber_all);
}

SEC("socket")
__failure
__log_level(1)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("iter_loop():")
__msg("  8: (bf) r1 = r6")
__msg("  9: (85) call bpf_iter_num_next")
__msg("  10: (15) if r0 == 0x0 goto pc+3")
__msg("  11: (07) r7 += 1")
__msg("  12: (25) if r7 > 0xf4240 goto pc+1")
__msg("  13: (05) goto pc-6")
__msg("#1 most visited simulated stacktrace (visited 142856 times):")
__msg("  iter_loop/8 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("#2 most visited simulated stacktrace (visited 142856 times):")
__msg("  iter_loop/9 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("    Most varying: R7 (frame 0)")
__msg("BPF program is too large. Processed 1000001 insn")
__naked void iter_loop(void)
{
	asm volatile ("					\
	r1 = r10;					\
	r1 += -16;					\
	w2 = 0;						\
	w3 = 1000000;					\
	call %[bpf_iter_num_new];			\
	r7 = 0;						\
	r6 = r10;					\
	r6 += -16;					\
1:	r1 = r6;					\
	call %[bpf_iter_num_next];			\
	if r0 == 0 goto 2f;				\
	r7 += 1;					\
	if r7 > 1000000 goto 2f;			\
	goto 1b;					\
2:	r1 = r6;					\
	call %[bpf_iter_num_destroy];			\
	r0 = r7;					\
	exit;						\
"	:
	: __imm(bpf_iter_num_new),
	  __imm(bpf_iter_num_next),
	  __imm(bpf_iter_num_destroy)
	: __clobber_all);
}

SEC("socket")
__failure
__log_level(1)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("iter_stack_varying():")
__msg("  10: (85) call bpf_iter_num_next")
__msg("#1 most visited simulated stacktrace (visited 111110 times):")
__msg("  iter_stack_varying/10 ({{.*}}/verifier_budget_report.c:{{[0-9]+}})")
__msg("    Most varying: fp-24 (frame 0)")
__msg("BPF program is too large. Processed 1000001 insn")
__naked void iter_stack_varying(void)
{
	asm volatile ("					\
	r1 = r10;					\
	r1 += -16;					\
	w2 = 0;						\
	w3 = 1000000;					\
	call %[bpf_iter_num_new];			\
	r8 = 0;						\
	*(u64 *)(r10 - 24) = r8;			\
	r6 = r10;					\
	r6 += -16;					\
1:	r1 = r6;					\
	call %[bpf_iter_num_next];			\
	if r0 == 0 goto 2f;				\
	r8 = *(u64 *)(r10 - 24);			\
	r8 += 1;					\
	*(u64 *)(r10 - 24) = r8;			\
	if r8 > 1000000 goto 2f;			\
	goto 1b;					\
2:	r1 = r6;					\
	call %[bpf_iter_num_destroy];			\
	r0 = *(u64 *)(r10 - 24);			\
	exit;						\
"	:
	: __imm(bpf_iter_num_new),
	  __imm(bpf_iter_num_next),
	  __imm(bpf_iter_num_destroy)
	: __clobber_all);
}

void iter_num_btf_fixup(void)
{
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
}

char _license[] SEC("license") = "GPL";
