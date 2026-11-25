// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic return hook for riscv.
 */

#include <linux/kprobes.h>
#include <linux/rethook.h>
#include "rethook.h"

/* This is called from arch_rethook_trampoline() */
unsigned long __used arch_rethook_trampoline_callback(struct pt_regs *regs)
{
	unsigned long frame = IS_ENABLED(CONFIG_UNWINDER_DWARF_CFI) ?
			      regs->sp : regs->s0;

	return rethook_trampoline_handler(regs, frame);
}

NOKPROBE_SYMBOL(arch_rethook_trampoline_callback);

void arch_rethook_prepare(struct rethook_node *rhn, struct pt_regs *regs, bool mcount)
{
	rhn->ret_addr = regs->ra;
	/*
	 * With -fomit-frame-pointer under CONFIG_UNWINDER_DWARF_CFI, nested
	 * functions share s0; key the rethook node on the function's entry SP
	 * (its DWARF CFA), which matches regs->sp at arch_rethook_trampoline.
	 */
	rhn->frame = IS_ENABLED(CONFIG_UNWINDER_DWARF_CFI) ?
		     regs->sp : regs->s0;

	/* replace return addr with trampoline */
	regs->ra = (unsigned long)arch_rethook_trampoline;
}

NOKPROBE_SYMBOL(arch_rethook_prepare);
