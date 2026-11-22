/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_UNWIND_USER_H
#define _ASM_X86_UNWIND_USER_H

#ifdef CONFIG_UNWIND_USER

#include <linux/unwind_dwarf_cfi.h>
#include <asm/ptrace.h>
#include <asm/uprobes.h>

/**
 * unwind_user_word_size() - Return the user-space word size in bytes on x86
 * @regs: User-mode register state.
 *
 * Return: 8 for 64-bit user mode, 4 for 32-bit IA-32/compat mode, or 0 for
 * VM86 mode stacks which cannot be unwound.
 */
static inline int unwind_user_word_size(struct pt_regs *regs)
{
	/* We can't unwind VM86 stacks */
	if (regs->flags & X86_VM_MASK)
		return 0;
	return user_64bit_mode(regs) ? 8 : 4;
}

/**
 * unwind_user_cfi_arch() - Populate x86/x86-64 DWARF register numbers
 * @ws: User word size in bytes (8 for x86-64, 4 for i386).
 * @arch: Output DWARF CFI architecture descriptor.
 *
 * Return: true if @ws is 4 or 8, false otherwise.
 */
static inline bool unwind_user_cfi_arch(unsigned int ws,
					struct dwarf_cfi_arch *arch)
{
	if (ws == 8) {
		*arch = (struct dwarf_cfi_arch){
			.ws	= 8,
			.sp_reg	= 7,	/* %rsp */
			.fp_reg	= 6,	/* %rbp */
			.ra_reg	= 16,	/* %rip */
		};
		return true;
	}
	if (ws == 4) {
		*arch = (struct dwarf_cfi_arch){
			.ws	= 4,
			.sp_reg	= 4,	/* %esp */
			.fp_reg	= 5,	/* %ebp */
			.ra_reg	= 8,	/* %eip */
		};
		return true;
	}
	return false;
}

#endif /* CONFIG_UNWIND_USER */

#ifdef CONFIG_HAVE_UNWIND_USER_FP

/* Standard x86 frame record: {saved_bp, ret_addr} at [bp, bp + 2 * ws). */
#define ARCH_INIT_USER_FP_FRAME(ws)			\
	.cfa_off	=  2*(ws),			\
	.ra_off		= -1*(ws),			\
	.fp_off		= -2*(ws),			\
	.use_fp		= true,

/* At function entry before push %rbp: return address is at [sp, sp + ws). */
#define ARCH_INIT_USER_FP_ENTRY_FRAME(ws)		\
	.cfa_off	=  1*(ws),			\
	.ra_off		= -1*(ws),			\
	.fp_off		= 0,				\
	.use_fp		= false,

/**
 * unwind_user_at_function_start() - Check if @regs is at a function entry point
 * @regs: User-mode register state.
 *
 * Return: true if stopped on an entry uprobe before the frame prologue ran.
 */
static inline bool unwind_user_at_function_start(struct pt_regs *regs)
{
	return is_uprobe_at_func_entry(regs);
}
#define unwind_user_at_function_start unwind_user_at_function_start

#endif /* CONFIG_HAVE_UNWIND_USER_FP */

#endif /* _ASM_X86_UNWIND_USER_H */
