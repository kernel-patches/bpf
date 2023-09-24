// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic return hook for riscv.
 */

#include <linux/kprobes.h>
#include <linux/rethook.h>
#include "rethook.h"

/* This is called from arch_rethook_trampoline() */
unsigned long __used arch_rethook_trampoline_callback(struct ftrace_regs *fregs)
{
	return rethook_trampoline_handler(fregs, fregs->regs.s0);
}

NOKPROBE_SYMBOL(arch_rethook_trampoline_callback);

void arch_rethook_prepare(struct rethook_node *rhn, struct ftrace_regs *fregs, bool mcount)
{
	rhn->ret_addr = fregs->regs.ra;
	rhn->frame = fregs->regs.s0;

	/* replace return addr with trampoline */
	fregs->regs.ra = (unsigned long)arch_rethook_trampoline;
}

NOKPROBE_SYMBOL(arch_rethook_prepare);
