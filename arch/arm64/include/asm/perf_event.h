/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __ASM_PERF_EVENT_H
#define __ASM_PERF_EVENT_H

#include <asm/stack_pointer.h>
#include <asm/ptrace.h>

#ifdef CONFIG_PERF_EVENTS
#define perf_arch_bpf_user_pt_regs(regs) &regs->user_regs
#endif

#ifdef CONFIG_UNWINDER_DWARF_CFI
void arm64_unwind_perf_caller_regs(struct pt_regs *regs, unsigned long pc,
				   unsigned long caller_ip, unsigned long sp,
				   unsigned long fp);

#define perf_arch_fetch_caller_regs(regs, __ip) do {			\
	unsigned long __here_pc, __here_fp;				\
	asm volatile("1: adr %0, 1b\n\t"				\
		     "mov %1, x29"					\
		     : "=r" (__here_pc), "=r" (__here_fp));		\
	arm64_unwind_perf_caller_regs((regs), __here_pc, (__ip),	\
				      current_stack_pointer, __here_fp);\
} while (0)
#else
#define perf_arch_fetch_caller_regs(regs, __ip) { \
	(regs)->pc = (__ip);    \
	(regs)->regs[29] = (unsigned long) __builtin_frame_address(0); \
	(regs)->sp = current_stack_pointer; \
	(regs)->pstate = PSR_MODE_EL1h;	\
}
#endif

#endif
