/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The interface between the architecture entries of bpf_throw() and the
 * generic unwinder.
 */
#ifndef _LINUX_BPF_THROW_H
#define _LINUX_BPF_THROW_H

/*
 * The callee-saved registers of the architecture that no BPF register maps
 * to, which the entries capture after R9 and the unwinder restores along
 * with R6..R9 when it discards frames: r12 on x86-64, which holds the arena
 * base, and x23..x28 on arm64, of which x23 is the stack pointer of the
 * stack in arena and x25..x28 are the BPF frame pointer, the tail call count
 * pointer, the private stack pointer and the arena base, while x24 is left
 * alone by JITed code but may be in use by the C code of the unwinder when
 * it enters the exception callback, whose epilogue never runs.
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
/* The size of struct bpf_throw_regs, for the entries: R0..R9 and the extra ones. */
#define BPF_THROW_REGS_SIZE		(8 * (10 + BPF_THROW_NR_EXTRA))

#ifndef __ASSEMBLER__
#include <linux/build_bug.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>

/*
 * The register file captured at a throw site: the BPF registers R0..R9, then
 * the extra callee-saved registers of the architecture; from R6 on, indexed
 * like bpf_prog_aux::callee_reg_off.
 */
struct bpf_throw_regs {
	u64 r[BPF_REG_10 + BPF_THROW_NR_EXTRA];
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
