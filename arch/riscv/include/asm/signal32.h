/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_SIGNAL32_H
#define __ASM_SIGNAL32_H

struct unwind_user_state;

#if IS_ENABLED(CONFIG_COMPAT)
int compat_setup_rt_frame(struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs);
bool compat_unwind_user_sigreturn(struct unwind_user_state *state);
#else
static inline
int compat_setup_rt_frame(struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs)
{
	return -1;
}
static inline
bool compat_unwind_user_sigreturn(struct unwind_user_state *state)
{
	return false;
}
#endif

#endif
