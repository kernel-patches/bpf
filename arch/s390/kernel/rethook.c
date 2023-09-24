// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/rethook.h>
#include <linux/kprobes.h>
#include "rethook.h"

void arch_rethook_prepare(struct rethook_node *rh, struct ftrace_regs *fregs, bool mcount)
{
	struct pt_regs *regs = (struct pt_regs *)fregs;
	rh->ret_addr = regs->gprs[14];
	rh->frame = regs->gprs[15];

	/* Replace the return addr with trampoline addr */
	regs->gprs[14] = (unsigned long)&arch_rethook_trampoline;
}
NOKPROBE_SYMBOL(arch_rethook_prepare);

void arch_rethook_fixup_return(struct ftrace_regs *fregs,
			       unsigned long correct_ret_addr)
{
	/* Replace fake return address with real one. */
	struct pt_regs *regs = (struct pt_regs *)fregs;
	regs->gprs[14] = correct_ret_addr;
}
NOKPROBE_SYMBOL(arch_rethook_fixup_return);

/*
 * Called from arch_rethook_trampoline
 */
unsigned long arch_rethook_trampoline_callback(struct ftrace_regs *fregs)
{
	return rethook_trampoline_handler(fregs, fregs->regs.gprs[15]);
}
NOKPROBE_SYMBOL(arch_rethook_trampoline_callback);

/* assembler function that handles the rethook must not be probed itself */
NOKPROBE_SYMBOL(arch_rethook_trampoline);
