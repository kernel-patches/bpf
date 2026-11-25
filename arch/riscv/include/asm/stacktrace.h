/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_RISCV_STACKTRACE_H
#define _ASM_RISCV_STACKTRACE_H

#include <linux/sched.h>
#include <asm/ptrace.h>

struct stackframe {
	unsigned long fp;
	unsigned long ra;
};

extern void notrace walk_stackframe(struct task_struct *task, struct pt_regs *regs,
				    bool (*fn)(void *, unsigned long), void *arg);
extern void dump_backtrace(struct pt_regs *regs, struct task_struct *task,
			   const char *loglvl);
extern char _start[];
asmlinkage void ret_from_fork_kernel_asm(void);
asmlinkage void ret_from_fork_user_asm(void);
extern unsigned long ret_from_fork_asm_end;
#ifdef CONFIG_IRQ_STACKS
extern unsigned long call_on_irq_stack_end;
#endif
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_ARGS
void ftrace_caller_saved(void);
void ftrace_caller_restore(void);
#endif

static inline bool on_thread_stack(void)
{
	return !(((unsigned long)(current->stack) ^ current_stack_pointer) & ~(THREAD_SIZE - 1));
}


#ifdef CONFIG_VMAP_STACK
DECLARE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)], overflow_stack);
#endif /* CONFIG_VMAP_STACK */

#endif /* _ASM_RISCV_STACKTRACE_H */
