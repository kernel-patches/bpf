/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <linux/bpf_throw.h>

/*
 * Native entry of the bpf_throw() kfunc. The verifier retargets the call to
 * bpf_throw() here, so the BPF register file of the throw site is still intact
 * on entry and x30 is the return address into the program. Push a frame record
 * whose link register is that address and save R6-R9, x19-x22, and the extra
 * callee-saved registers x23-x28 below it as a struct bpf_throw_regs: saved[i]
 * sits at [sp + 16 + 8 * i]. Then hand it to bpf_throw_unwind(), which never
 * returns.
 */
SYM_FUNC_START(bpf_throw_entry)
	stp	x29, x30, [sp, #-(16 + BPF_THROW_REGS_SIZE)]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]

	/* bpf_throw_unwind(regs, cookie); the cookie is R1 of the caller. */
	mov	x1, x0
	add	x0, sp, #16
	bl	bpf_throw_unwind
	brk	#0x1
SYM_FUNC_END(bpf_throw_entry)
