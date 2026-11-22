/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_ARM64_UNWIND_USER_H
#define __ASM_ARM64_UNWIND_USER_H

#ifdef CONFIG_UNWIND_USER

#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/unwind_dwarf_cfi.h>
#include <linux/unwind_user_types.h>
#include <asm/compiler.h>
#include <asm/ptrace.h>

/**
 * unwind_user_word_size() - Return the user-space word size in bytes on arm64
 * @regs: User-mode register state.
 *
 * Return: 4 for AArch32 compat user mode, or 8 for AArch64 user mode.
 */
static inline int unwind_user_word_size(struct pt_regs *regs)
{
	return compat_user_mode(regs) ? 4 : 8;
}

/**
 * unwind_user_frame_pointer() - Fetch the user frame pointer from @regs
 * @regs: User-mode register state.
 *
 * Return: r11 (compat_fp) for AArch32 compat tasks, or x29 for AArch64 tasks.
 */
static inline unsigned long unwind_user_frame_pointer(struct pt_regs *regs)
{
	return compat_user_mode(regs) ? regs->compat_fp : frame_pointer(regs);
}
#define unwind_user_frame_pointer unwind_user_frame_pointer

/**
 * unwind_user_link_register() - Fetch the user link register from @regs
 * @regs: User-mode register state.
 * @ra: Output link register value (r14 for AArch32 compat, x30 for AArch64).
 *
 * Return: Always true on arm64 because a link register is architecturally
 * present in both AArch64 and AArch32 execution states.
 */
static inline bool unwind_user_link_register(struct pt_regs *regs,
					     unsigned long *ra)
{
	if (compat_user_mode(regs))
		*ra = regs->compat_lr;
	else
		*ra = procedure_link_pointer(regs);
	return true;
}
#define unwind_user_link_register unwind_user_link_register

/**
 * unwind_user_strip_pac() - Strip user pointer authentication bits on arm64
 * @ip: Recovered user return address.
 * @ra_signed: Whether CFI marked the return address as PAC-signed (unused;
 *             arm64 strips user instruction PAC bits unconditionally via the
 *             task's configured pointer authentication mask).
 *
 * Return: @ip unchanged for AArch32 compat tasks, or @ip with user instruction
 * PAC bits stripped for AArch64 tasks.
 */
static inline unsigned long unwind_user_strip_pac(unsigned long ip,
						  bool ra_signed)
{
	if (IS_ENABLED(CONFIG_COMPAT) &&
	    compat_user_mode(task_pt_regs(current)))
		return ip;
	return ptrauth_strip_user_insn_pac(ip);
}
#define unwind_user_strip_pac unwind_user_strip_pac

/**
 * unwind_user_cfi_arch() - Populate AArch64/AArch32 DWARF register numbers
 * @ws: User word size in bytes (8 for AArch64, 4 for AArch32 compat).
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
			.sp_reg	= 31,	/* sp */
			.fp_reg	= 29,	/* x29 */
			.ra_reg	= 30,	/* x30 (lr) */
		};
		return true;
	}
	if (ws == 4) {
		*arch = (struct dwarf_cfi_arch){
			.ws	= 4,
			.sp_reg	= 13,	/* r13 (sp) */
			.fp_reg	= 11,	/* r11 (fp) */
			.ra_reg	= 14,	/* r14 (lr) */
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
 * AArch64 PCS stores {fp, lr} at [fp, fp + 16), while 32-bit AArch32 compat
 * APCS stores struct compat_frame_tail {fp, sp, lr} at [compat_fp - 12, compat_fp).
 */
#define ARCH_INIT_USER_FP_FRAME(ws)			\
	.cfa_off	= (ws) == 8 ? 2 * (ws) : 0,	\
	.ra_off		= -1 * (ws),			\
	.fp_off		= (ws) == 8 ? -2 * (ws) : -3 * (ws), \
	.use_fp		= true,

#endif /* CONFIG_HAVE_UNWIND_USER_FP */

#endif /* __ASM_ARM64_UNWIND_USER_H */
