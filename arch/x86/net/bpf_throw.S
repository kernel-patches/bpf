/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <asm/nospec-branch.h>

	.code64
	.section .text, "ax"

/*
 * Native entry of the bpf_throw() kfunc. The verifier retargets the call to
 * bpf_throw() here, so the BPF register file of the throw site is still intact
 * on entry. Capture it on the stack as a struct bpf_throw_regs, along with
 * r12, the callee-saved register no BPF register maps to, and hand it to
 * bpf_throw_unwind(), which never returns.
 */
SYM_FUNC_START(bpf_throw_entry)
	ANNOTATE_NOENDBR

	/* Setup frame. */
	pushq %rbp
	movq %rsp, %rbp

	/* Save r12, then R9..R0 so that [rsp + 8 * i] is r[i]. */
	pushq %r12	/* r[10] */
	pushq %r15	/* R9 */
	pushq %r14	/* R8 */
	pushq %r13	/* R7 */
	pushq %rbx	/* R6 */
	pushq %r8	/* R5 */
	pushq %rcx	/* R4 */
	pushq %rdx	/* R3 */
	pushq %rsi	/* R2 */
	pushq %rdi	/* R1 */
	pushq %rax	/* R0 */

	/* bpf_throw_unwind(regs, cookie); the cookie is R1 of the caller. */
	movq %rdi, %rsi
	movq %rsp, %rdi

	/* Emit call depth accounting for call below. */
	CALL_DEPTH_ACCOUNT
	call bpf_throw_unwind
	ud2
SYM_FUNC_END(bpf_throw_entry)
