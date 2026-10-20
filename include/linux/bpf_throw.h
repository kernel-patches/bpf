/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The interface between the architecture entries of bpf_throw() and the
 * generic unwinder.
 */
#ifndef _LINUX_BPF_THROW_H
#define _LINUX_BPF_THROW_H

/* The callee-saved registers the unwinder tracks: R6..R9. */
#define BPF_THROW_NR_CALLEE_SAVED	4
/* The size of struct bpf_throw_regs, for the entries. */
#define BPF_THROW_REGS_SIZE		(8 * BPF_THROW_NR_CALLEE_SAVED)

#ifndef __ASSEMBLER__
#include <linux/build_bug.h>
#include <linux/types.h>

/*
 * The callee-saved registers captured at a throw site, indexed like
 * bpf_prog_aux::callee_reg_off.
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
