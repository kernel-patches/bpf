// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <asm/asm-offsets.h>

SYM_CODE_START(arch_bpf_timed_may_goto)
	/*
	 * Create room for spilling registers and link register.
	 * We need 56 bytes but stack must be 16-byte aligned.
	 */
	sub sp, sp, #64

	/* Save r0-r5. */
	stp x7, x0, [sp]
	stp x1, x2, [sp, #16]
	stp x3, x4, [sp, #32]
	/* Save link register. */
	str x30, [sp, #48]

	/*
	 * x9 passes us stack depth, load the pointer to count and timestamp as
	 * first argument to the call below.
	 */
	add x0, x25, x9
	bl bpf_check_timed_may_goto

	/* BPF_REG_AX=x9 will be stored into count, so move return value to it. */
	mov x9, x0

	/* Restore link register. */
	ldr x30, [sp, #48]
	/* Restore r5-r0 */
	ldp x3, x4, [sp, #32]
	ldp x1, x2, [sp, #16]
	ldp x7, x0, [sp]

	/* Restore stack pointer. */
	add sp, sp, #64

	ret
SYM_CODE_END(arch_bpf_timed_may_goto)
