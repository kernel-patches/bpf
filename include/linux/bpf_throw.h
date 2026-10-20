/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The interface between the architecture entries of bpf_throw() and the
 * generic unwinder.
 */
#ifndef _LINUX_BPF_THROW_H
#define _LINUX_BPF_THROW_H

/*
 * The callee-saved registers of the architecture that no BPF register maps
 * to, which the unwinder restores along with R6..R9 when it discards frames:
 * r12 on x86-64, which holds the arena base, and x23..x28 on arm64, of which
 * x25..x28 are the BPF frame pointer, the tail call count pointer, the
 * private stack pointer and the arena base, while x23 and x24 are left alone
 * by JITed code but may be in use by the C code of the unwinder when it
 * enters the exception callback, whose epilogue never runs.
 */
#if defined(CONFIG_X86_64)
#define BPF_THROW_NR_EXTRA	1
#elif defined(CONFIG_ARM64)
#define BPF_THROW_NR_EXTRA	6
#else
#define BPF_THROW_NR_EXTRA	0
#endif
/* The callee-saved registers the unwinder tracks: R6..R9, then the extra ones. */
#define BPF_THROW_NR_CALLEE_SAVED	(4 + BPF_THROW_NR_EXTRA)
/* The size of struct bpf_throw_regs, for the entries. */
#define BPF_THROW_REGS_SIZE		(8 * BPF_THROW_NR_CALLEE_SAVED)

#ifndef __ASSEMBLER__
#include <linux/build_bug.h>
#include <linux/types.h>

/*
 * The callee-saved registers captured at a throw site, R6..R9 then the extra
 * ones of the architecture, indexed like bpf_prog_aux::callee_reg_off.
 */
struct bpf_throw_regs {
	u64 saved[BPF_THROW_NR_CALLEE_SAVED];
};
static_assert(sizeof(struct bpf_throw_regs) == BPF_THROW_REGS_SIZE);

void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie);
/* The native entry of bpf_throw(), on an architecture that has one. */
void bpf_throw_entry(void);
void *bpf_arch_throw_entry(void);
#endif /* __ASSEMBLER__ */

#endif /* _LINUX_BPF_THROW_H */
