/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Feng Jiang <jiangfeng@kylinos.cn> */

#include <linux/linkage.h>
#include <asm/asm.h>

/*
 * Trampoline for the BPF timed may_goto loop bound. Custom calling convention:
 *	- input:  stack offset in BPF_REG_AX (t0)
 *	- output: updated count in BPF_REG_AX (t0)
 *
 * Calls bpf_check_timed_may_goto(ptr) with the standard RISC-V ABI, where
 * ptr = BPF_REG_FP (s5) + BPF_REG_AX (t0). BPF R0-R5 (a5, a0-a4) are saved
 * across the call; BPF_REG_FP (s5) is callee-saved and needs no saving.
 */

SYM_FUNC_START(arch_bpf_timed_may_goto)
	addi	sp, sp, -64
	sd	ra, 56(sp)
	sd	s0, 48(sp)
	addi	s0, sp, 64

	/* Save BPF registers R0-R5 (a5, a0-a4) */
	sd	a5, 40(sp)
	sd	a0, 32(sp)
	sd	a1, 24(sp)
	sd	a2, 16(sp)
	sd	a3, 8(sp)
	sd	a4, 0(sp)

	add	a0, t0, s5
	call	bpf_check_timed_may_goto
	mv	t0, a0

	/* Restore BPF registers R0-R5 */
	ld	a4, 0(sp)
	ld	a3, 8(sp)
	ld	a2, 16(sp)
	ld	a1, 24(sp)
	ld	a0, 32(sp)
	ld	a5, 40(sp)

	ld	s0, 48(sp)
	ld	ra, 56(sp)
	addi	sp, sp, 64
	ret
SYM_FUNC_END(arch_bpf_timed_may_goto)
