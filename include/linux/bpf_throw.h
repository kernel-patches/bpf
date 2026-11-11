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

/*
 * bpf_throw_unwind() never returns: it transfers to a JITed callback, which
 * returns to the kernel code that called the program. With a shadow call
 * stack the return address its prologue pushed would never be popped, and the
 * program's caller would pop it in place of its own. __noscs keeps a static
 * shadow call stack out of the function. A dynamic one is patched in at boot
 * in place of the pointer authentication of every function that has it, see
 * UNWIND_PATCH_PAC_INTO_SCS, so the function has to do without that as well,
 * which costs it nothing, as it never returns through it; the branch target
 * identification stays.
 */
#if defined(CONFIG_DYNAMIC_SCS) && defined(CONFIG_ARM64_BTI_KERNEL)
#define __bpf_unwind_entry	__noscs __attribute__((__target__("branch-protection=bti")))
#elif defined(CONFIG_DYNAMIC_SCS)
#define __bpf_unwind_entry	__noscs __attribute__((__target__("branch-protection=none")))
#else
#define __bpf_unwind_entry	__noscs
#endif

void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie);
/* The native entry of bpf_throw(), on an architecture that has one. */
void bpf_throw_entry(void);
void *bpf_arch_throw_entry(void);
#endif /* __ASSEMBLER__ */

#endif /* _LINUX_BPF_THROW_H */
