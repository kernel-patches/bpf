// SPDX-License-Identifier: GPL-2.0
/*
 * Generic return hook for LoongArch.
 */

#include <linux/kprobes.h>
#include <linux/rethook.h>
#include "rethook.h"

/* This is called from arch_rethook_trampoline() */
unsigned long __used arch_rethook_trampoline_callback(struct ftrace_regs *fregs)
{
	return rethook_trampoline_handler(fregs, 0);
}
NOKPROBE_SYMBOL(arch_rethook_trampoline_callback);

void arch_rethook_prepare(struct rethook_node *rhn, struct ftrace_regs *fregs, bool mcount)
{
	rhn->frame = 0;
	rhn->ret_addr = fregs->regs.regs[1];

	/* replace return addr with trampoline */
	fregs->regs.regs[1] = (unsigned long)arch_rethook_trampoline;
}
NOKPROBE_SYMBOL(arch_rethook_prepare);

/* ASM function that handles the rethook must not be probed itself */
NOKPROBE_SYMBOL(arch_rethook_trampoline);
