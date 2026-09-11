// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

/*
 * Running an exception cleanup landing pad on behalf of a BPF frame that is
 * about to be discarded. See the runtime section of kernel/bpf/exception.c.
 *
 * The x86-64 BPF JIT prologue spills, in this order, r12, rbx, r13, r14 and
 * r15 -- so within the spill area the lowest address holds r15 and the
 * highest r12. The throw-site spill the JIT emits uses the same layout, so
 * the routine below reads both the same way:
 *
 *	spill_base + 0		BPF r9  (r15)
 *	spill_base + 8		BPF r8  (r14)
 *	spill_base + 16		BPF r7  (r13)
 *	spill_base + 24		BPF r6  (rbx)
 *	spill_base + 32		r12 (arena base, not a BPF register)
 */

	.code64
	.section .text, "ax"

/*
 * void arch_bpf_run_cleanup_pad(u64 pad, u64 frame_fp, u64 spill_base)
 *
 * rdi = native address of the landing pad
 * rsi = frame pointer of the frame the pad belongs to
 * rdx = spill area holding that frame's BPF callee-saved registers
 *
 * Give the pad the register state of its own frame and call it. The pad ends
 * in the bare return the JIT emits for its bpf_unwind_resume(), so it comes
 * back here rather than returning to its frame's caller. It runs on this
 * stack, far below the frame it is cleaning up after, so nothing it calls can
 * reach into that frame.
 *
 * rbp is BPF r10, so it is spent from the moment the pad's frame pointer goes
 * in and everything after the call is addressed off rsp.
 */
SYM_FUNC_START(arch_bpf_run_cleanup_pad)
	ANNOTATE_NOENDBR

	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	/* Keep the pad's entry rsp congruent to a normal call's. */
	subq $8, %rsp

	movq 0(%rdx), %r15
	movq 8(%rdx), %r14
	movq 16(%rdx), %r13
	movq 24(%rdx), %rbx
	movq 32(%rdx), %r12
	movq %rsi, %rbp

	/* CALL_NOSPEC needs the target in a register; rcx is BPF r4, dead. */
	movq %rdi, %rcx

	/*
	 * BPF r0. LLVM names it as both the exception pointer and the
	 * selector register, so the pad reads it before anything else and is
	 * free to store what it read -- it must not be whatever the kernel
	 * left in rax. The verifier models exactly this constant; see
	 * BPF_PAD_ENTRY_R0.
	 */
	movq $1, %rax

	CALL_NOSPEC rcx

	addq $8, %rsp
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	RET
SYM_FUNC_END(arch_bpf_run_cleanup_pad)
