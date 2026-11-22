/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UNWIND_USER_H
#define _LINUX_UNWIND_USER_H

#include <linux/unwind_user_types.h>
#include <asm/unwind_user.h>

#ifndef CONFIG_HAVE_UNWIND_USER_FP

#define ARCH_INIT_USER_FP_FRAME(ws)

#endif

#ifndef ARCH_INIT_USER_FP_ENTRY_FRAME
#define ARCH_INIT_USER_FP_ENTRY_FRAME(ws)
#endif

#ifndef unwind_user_at_function_start
/**
 * unwind_user_at_function_start() - Default stub for function-entry detection
 * @regs: User-mode register state.
 *
 * Return: false when the architecture does not override entry detection.
 */
static inline bool unwind_user_at_function_start(struct pt_regs *regs)
{
	return false;
}
#define unwind_user_at_function_start unwind_user_at_function_start
#endif

#ifndef unwind_user_frame_pointer
/**
 * unwind_user_frame_pointer() - Default helper returning @regs's frame pointer
 * @regs: User-mode register state.
 *
 * Return: Architectural user frame pointer from frame_pointer(@regs).
 */
static inline unsigned long unwind_user_frame_pointer(struct pt_regs *regs)
{
	return frame_pointer(regs);
}
#define unwind_user_frame_pointer unwind_user_frame_pointer
#endif

#ifndef unwind_user_link_register
/**
 * unwind_user_link_register() - Default stub for architectures without an LR
 * @regs: User-mode register state.
 * @ra: Unused output link register pointer.
 *
 * Return: false on architectures where calls push the return address on stack.
 */
static inline bool unwind_user_link_register(struct pt_regs *regs,
					     unsigned long *ra)
{
	return false;
}
#define unwind_user_link_register unwind_user_link_register
#endif

#ifndef unwind_user_strip_pac
/**
 * unwind_user_strip_pac() - Default no-op PAC stripping helper
 * @ip: Recovered user instruction pointer.
 * @ra_signed: Whether CFI marked the return address as PAC-signed.
 *
 * Return: @ip unchanged on architectures without pointer authentication.
 */
static inline unsigned long unwind_user_strip_pac(unsigned long ip,
						  bool ra_signed)
{
	return ip;
}
#define unwind_user_strip_pac unwind_user_strip_pac
#endif

#ifndef unwind_user_sigreturn
/**
 * unwind_user_sigreturn() - Default stub for arch signal-trampoline unwinding
 * @state: Current user unwind state.
 *
 * Return: false on architectures whose signal trampolines unwind via CFI/FP.
 */
static inline bool unwind_user_sigreturn(struct unwind_user_state *state)
{
	return false;
}
#define unwind_user_sigreturn unwind_user_sigreturn
#endif

#ifdef CONFIG_HAVE_UNWIND_USER_CFI
int unwind_user_next_cfi(struct unwind_user_state *state,
			 struct unwind_user_frame *out_frame, bool *out_signal);
#else
static inline int unwind_user_next_cfi(struct unwind_user_state *state,
				       struct unwind_user_frame *out_frame,
				       bool *out_signal)
{
	return -EINVAL;
}
#endif

int unwind_user(struct unwind_stacktrace *trace, unsigned int max_entries);

#endif /* _LINUX_UNWIND_USER_H */
