/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_UNWIND_USER_H
#define _ASM_RISCV_UNWIND_USER_H

#ifdef CONFIG_UNWIND_USER

#include <linux/compat.h>
#include <linux/unwind_dwarf_cfi.h>
#include <linux/unwind_user_types.h>
#include <asm/ptrace.h>

/**
 * unwind_user_word_size() - Return the user-space word size in bytes on RISC-V
 * @regs: User-mode register state.
 *
 * Return: 4 for RV32 compat user tasks, or sizeof(unsigned long) otherwise.
 */
static inline int unwind_user_word_size(struct pt_regs *regs)
{
	if (IS_ENABLED(CONFIG_COMPAT) && is_compat_task())
		return 4;
	return sizeof(unsigned long);
}

/**
 * unwind_user_link_register() - Fetch the user link register (ra/x1) from @regs
 * @regs: User-mode register state.
 * @ra: Output link register value.
 *
 * Return: Always true on RISC-V.
 */
static inline bool unwind_user_link_register(struct pt_regs *regs,
					     unsigned long *ra)
{
	*ra = regs->ra;
	return true;
}

#define unwind_user_link_register unwind_user_link_register

/**
 * unwind_user_cfi_arch() - Populate RISC-V DWARF register numbers
 * @ws: User word size in bytes (4 for RV32, 8 for RV64).
 * @arch: Output DWARF CFI architecture descriptor.
 *
 * Return: true if @ws is 4 or 8, false otherwise.
 */
static inline bool unwind_user_cfi_arch(unsigned int ws,
					struct dwarf_cfi_arch *arch)
{
	if (ws == 8 || ws == 4) {
		*arch = (struct dwarf_cfi_arch){
			.ws	= (u8)ws,
			.sp_reg	= 2,	/* sp (x2) */
			.fp_reg	= 8,	/* s0/fp (x8) */
			.ra_reg	= 1,	/* ra (x1) */
		};
		return true;
	}
	return false;
}

bool unwind_user_sigreturn(struct unwind_user_state *state);
#define unwind_user_sigreturn unwind_user_sigreturn

#endif /* CONFIG_UNWIND_USER */

#ifdef CONFIG_HAVE_UNWIND_USER_FP

/*
 * Standard RISC-V psABI frame record stores {saved_s0, saved_ra} at
 * [s0 - 2 * ws, s0), with s0 pointing to the caller's stack pointer (CFA).
 */
#define ARCH_INIT_USER_FP_FRAME(ws)			\
	.cfa_off	=  0,				\
	.ra_off		= -1 * (ws),			\
	.fp_off		= -2 * (ws),			\
	.use_fp		= true,

#endif /* CONFIG_HAVE_UNWIND_USER_FP */

#endif /* _ASM_RISCV_UNWIND_USER_H */
