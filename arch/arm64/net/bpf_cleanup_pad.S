/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf_cleanup_abi.h>
#include <linux/linkage.h>

/*
 * A frame's prologue pushes the tail call counter pair, and then -- once
 * bpf_cleanup_force_spill() says so -- x19/x20, x21/x22, x23/x24, x25/x26 and
 * x27/x28. Each A64_PUSH pre-decrements, so the lowest address of the spill
 * area holds x27 and the highest x20:
 *
 *	spill_base + 0		x27 (private stack pointer)
 *	spill_base + 8		x28 (arena base)
 *	spill_base + 16		x25 (BPF r10, the frame pointer)
 *	spill_base + 24		x26 (tail call counter pointer)
 *	spill_base + 32		x23  -- the pad's own, see below
 *	spill_base + 40		x24  -- likewise
 *	spill_base + 48		x21 (BPF r8)
 *	spill_base + 56		x22 (BPF r9)
 *	spill_base + 64		x19 (BPF r6)
 *	spill_base + 72		x20 (BPF r7)
 *
 * Neither x23 nor x24 is restored from that spill: the pad has its own use for
 * both. bpf2a64[] maps nothing to either -- they are pushed only to keep the
 * frame shape the exception callback expects -- so nothing else in generated
 * code touches them, and being callee-saved they survive every call the pad
 * makes.
 *
 * x23 is the pad's return address. Unlike x86-64 a pad cannot simply return:
 * every call it makes clobbers x30, so nothing is left to return through by
 * the time it reaches its resume. The JIT emits "br x23" for the pad's
 * bpf_unwind_resume() and this routine puts .Lcleanup_pad_done there.
 *
 * x24 is where the pad's frame is anchored. Generated code addresses the BPF
 * frame through the stack pointer, which here is this routine's rather than
 * the unwinding frame's, so the JIT has the pad recompute the equivalent from
 * BPF r10 on entry and address its frame off x24 for as long as it runs.
 *
 * Both of those branches are indirect, so both targets carry a BTI landing
 * marker: the JIT emits one at each pad, and .Lcleanup_pad_done below has one
 * of its own.
 */

	.text

/*
 * void arch_bpf_run_cleanup_pad(u64 pad, u64 frame_fp, u64 spill_base)
 *
 * x0 = native address of the landing pad
 * x1 = frame pointer of the frame the pad belongs to (unused here: BPF r10 is
 *      x25, which the spill area already holds)
 * x2 = spill area holding that frame's BPF callee-saved registers
 *
 * Give the pad the register state of its own frame and call it. It runs on
 * this stack, far below the frame it is cleaning up after, so nothing it
 * calls can reach into that frame.
 */
SYM_FUNC_START(arch_bpf_run_cleanup_pad)
	/* Save the kernel's callee-saved registers; the pad owns them next. */
	stp	x29, x30, [sp, #-96]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]

	/* x9 is BPF_REG_AX, so the pad's address does not stay in BPF r1. */
	mov	x9, x0

	ldp	x27, x28, [x2, #0]
	ldp	x25, x26, [x2, #16]
	ldp	x21, x22, [x2, #48]
	ldp	x19, x20, [x2, #64]

	/* BPF r0 (x8) on the way into a pad, not whatever the kernel left. */
	mov	x8, #BPF_PAD_ENTRY_R0

	/* Where the pad's resume branches back to. */
	adr	x23, .Lcleanup_pad_done

	br	x9

.Lcleanup_pad_done:
	/* Reached by the pad's "br x23", so it is an indirect branch target. */
	bti	j
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	x25, x26, [sp, #64]
	ldp	x27, x28, [sp, #80]
	ldp	x29, x30, [sp], #96
	ret
SYM_FUNC_END(arch_bpf_run_cleanup_pad)
