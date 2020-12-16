/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * BPF JIT compiler for PPC32
 *
 */
#ifndef _BPF_JIT32_H
#define _BPF_JIT32_H

#include "bpf_jit.h"

/*
 * Stack layout:
 *
 *		[	prev sp		] <-------------
 *		[   nv gpr save area	] 16 * 4	|
 * fp (r31) -->	[   ebpf stack space	] upto 512	|
 *		[     frame header	] 16		|
 * sp (r1) --->	[    stack pointer	] --------------
 */

/* for gpr non volatile registers r18 to r31 (14) + r17 for tail call + alignment */
#define BPF_PPC_STACK_SAVE	(14 * 4 + 4 + 4)
/* stack frame, ensure this is quadword aligned */
#define BPF_PPC_STACKFRAME(ctx)	(STACK_FRAME_MIN_SIZE + BPF_PPC_STACK_SAVE + (ctx)->stack_size)

#ifndef __ASSEMBLY__

/* BPF register usage */
#define TMP_REG	(MAX_BPF_JIT_REG + 0)

/* BPF to ppc register mappings */
static const int b2p[] = {
	/* function return value */
	[BPF_REG_0] = 12,
	/* function arguments */
	[BPF_REG_1] = 4,
	[BPF_REG_2] = 6,
	[BPF_REG_3] = 8,
	[BPF_REG_4] = 10,
	[BPF_REG_5] = 22,
	/* non volatile registers */
	[BPF_REG_6] = 24,
	[BPF_REG_7] = 26,
	[BPF_REG_8] = 28,
	[BPF_REG_9] = 30,
	/* frame pointer aka BPF_REG_10 */
	[BPF_REG_FP] = 31,
	/* eBPF jit internal registers */
	[BPF_REG_AX] = 20,
	[TMP_REG] = 18,
};

/* PPC NVR range -- update this if we ever use NVRs below r18 */
#define BPF_PPC_NVR_MIN		18

#endif /* !__ASSEMBLY__ */

#endif
