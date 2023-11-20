/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CFI_H
#define _ASM_X86_CFI_H

/*
 * Clang Control Flow Integrity (CFI) support.
 *
 * Copyright (C) 2022 Google LLC
 */
#include <linux/bug.h>

enum cfi_mode {
	CFI_DEFAULT,
	CFI_OFF,
	CFI_KCFI,
	CFI_FINEIBT,
};

extern enum cfi_mode cfi_mode;

struct pt_regs;

#ifdef CONFIG_CFI_CLANG
enum bug_trap_type handle_cfi_failure(struct pt_regs *regs);
#define __bpfcall
extern u32 cfi_bpf_hash;
#else
static inline enum bug_trap_type handle_cfi_failure(struct pt_regs *regs)
{
	return BUG_TRAP_TYPE_NONE;
}
#define cfi_bpf_hash 0U
#endif /* CONFIG_CFI_CLANG */

#endif /* _ASM_X86_CFI_H */
