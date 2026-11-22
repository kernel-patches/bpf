/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 SiFive
 * Copyright (C) 2018 Andes Technology Corporation
 *
 */

#ifndef _ASM_RISCV_PERF_EVENT_H
#define _ASM_RISCV_PERF_EVENT_H

#ifdef CONFIG_PERF_EVENTS
#include <linux/perf_event.h>
#define perf_arch_bpf_user_pt_regs(regs) (struct user_regs_struct *)regs

#ifdef CONFIG_UNWINDER_DWARF_CFI
void riscv_unwind_perf_caller_regs(struct pt_regs *regs, unsigned long pc,
				   unsigned long caller_ip, unsigned long sp,
				   unsigned long fp);

#define perf_arch_fetch_caller_regs(regs, __ip) do {			\
	unsigned long __here_pc, __here_fp;				\
	asm volatile("1: auipc %0, 0\n\t"				\
		     "mv %1, s0"					\
		     : "=r" (__here_pc), "=r" (__here_fp));		\
	riscv_unwind_perf_caller_regs((regs), __here_pc, (__ip),	\
				      current_stack_pointer, __here_fp);\
} while (0)
#else
#define perf_arch_fetch_caller_regs(regs, __ip) { \
	(regs)->epc = (__ip); \
	(regs)->s0 = (unsigned long) __builtin_frame_address(0); \
	(regs)->sp = current_stack_pointer; \
	(regs)->status = SR_PP; \
}
#endif
#endif

#endif /* _ASM_RISCV_PERF_EVENT_H */
