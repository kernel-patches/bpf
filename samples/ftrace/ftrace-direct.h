/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SAMPLES_FTRACE_DIRECT_H
#define _SAMPLES_FTRACE_DIRECT_H

#include <linux/stringify.h>

/*
 * A direct-call trampoline is entered with no lock, refcount or RCU marker
 * held; only Tasks RCU keeps it (and, for a module, its text) alive while a
 * task is inside it or preempted in something it called.  On architectures
 * that select ARCH_HAS_RCU_TASKS_PREEMPT_QS a preemption is a Tasks RCU
 * quiescent state unless current->rcu_tramp_nesting is non-zero, so the
 * trampoline must raise it before calling out and drop it afterwards, exactly
 * like the ftrace and BPF trampolines do.  See rcu_tasks_trampoline_enter()
 * and register_ftrace_direct().  The instructions before the increment and
 * after the decrement are covered by ftrace_direct_mark_module().
 *
 * These expand to instruction strings for use inside the samples' asm()
 * trampolines.  The scratch register is caller-saved and not an argument
 * register, so it is dead on entry to and exit from an fentry trampoline.
 *
 * The generated asm-offsets.h is only pulled in on the architectures that need
 * it here: it is not generally safe to include from C (e.g. PPC32's TASK_SIZE
 * and arm64's TRAMP_VALIAS clash with the C definitions), which is why the
 * samples themselves guard their own include of it.
 */
#if defined(CONFIG_TASKS_RCU) && defined(CONFIG_X86_64)

#include <asm/asm-offsets.h>

#define RCU_TASKS_TRAMP_ENTER						\
	"	movq %gs:current_task(%rip), %r11\n"				\
	"	incl " __stringify(TASK_rcu_tramp_nesting) "(%r11)\n"
#define RCU_TASKS_TRAMP_EXIT						\
	"	movq %gs:current_task(%rip), %r11\n"				\
	"	decl " __stringify(TASK_rcu_tramp_nesting) "(%r11)\n"

#elif defined(CONFIG_TASKS_RCU) && defined(CONFIG_ARM64)

/* arm64's asm-offsets.h redefines TRAMP_VALIAS from <asm/fixmap.h>. */
#pragma push_macro("TRAMP_VALIAS")
#undef TRAMP_VALIAS
#include <asm/asm-offsets.h>
#pragma pop_macro("TRAMP_VALIAS")

#define RCU_TASKS_TRAMP_ENTER						\
	"	mrs	x12, sp_el0\n"						\
	"	ldr	w13, [x12, #" __stringify(TSK_RCU_TRAMP_NESTING) "]\n"	\
	"	add	w13, w13, #1\n"						\
	"	str	w13, [x12, #" __stringify(TSK_RCU_TRAMP_NESTING) "]\n"
#define RCU_TASKS_TRAMP_EXIT						\
	"	mrs	x12, sp_el0\n"						\
	"	ldr	w13, [x12, #" __stringify(TSK_RCU_TRAMP_NESTING) "]\n"	\
	"	sub	w13, w13, #1\n"						\
	"	str	w13, [x12, #" __stringify(TSK_RCU_TRAMP_NESTING) "]\n"

#else

#define RCU_TASKS_TRAMP_ENTER
#define RCU_TASKS_TRAMP_EXIT

#endif

#endif /* _SAMPLES_FTRACE_DIRECT_H */
