/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LOONGARCH_RETHOOK_H
#define __LOONGARCH_RETHOOK_H

unsigned long arch_rethook_trampoline_callback(struct ftrace_regs *fregs);
void arch_rethook_prepare(struct rethook_node *rhn, struct ftrace_regs *fregs, bool mcount);

#endif
