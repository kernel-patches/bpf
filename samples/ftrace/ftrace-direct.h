/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SAMPLES_FTRACE_DIRECT_H
#define _SAMPLES_FTRACE_DIRECT_H

#include <linux/stringify.h>

/*
 * A direct-call trampoline is entered with no lock, refcount or RCU marker
 * held; only Tasks RCU keeps it (and, for a module, its text) alive while a
 * task is inside it or preempted in something it called.  On architectures
 * that select HAVE_RCU_TRAMPOLINE_READERS, Tasks RCU only waits for such a
 * task while it is a Tasks Trace RCU reader, so the trampoline must enter one
 * before calling out and leave it afterwards, exactly like the ftrace and BPF
 * trampolines do.  See register_ftrace_direct().  The instructions before the
 * lock and after the unlock are covered by ftrace_direct_mark_module().
 *
 * These are rcu_read_lock_trace() / rcu_read_unlock_trace() open-coded as
 * instruction strings for use inside the samples' asm() trampolines, after
 * the versions in arch/x86/kernel/ftrace_64.S and
 * arch/arm64/kernel/entry-ftrace.S.  The scratch registers are caller-saved
 * and not argument registers, so they are dead on entry to and exit from an
 * fentry trampoline; the flags are clobbered.
 *
 * The generated asm-offsets.h is only pulled in on the architectures that need
 * it here: it is not generally safe to include from C (e.g. PPC32's TASK_SIZE
 * and arm64's TRAMP_VALIAS clash with the C definitions).
 */
#if defined(CONFIG_TASKS_RCU_TRAMPOLINE_READERS) && defined(CONFIG_X86_64)

#include <asm/asm-offsets.h>

#ifndef CONFIG_TASKS_TRACE_RCU_NO_MB
#define TRACE_RCU_MB	"	lock addl $0, -4(%rsp)\n"
#else
#define TRACE_RCU_MB
#endif

#define TRACE_RCU_READ_LOCK							\
	"	movq %gs:current_task(%rip), %r11\n"					\
	"	movl " __stringify(TASK_trc_reader_nesting) "(%r11), %r10d\n"		\
	"	incl " __stringify(TASK_trc_reader_nesting) "(%r11)\n"		\
	"	testl %r10d, %r10d\n"							\
	"	jnz 771f\n"								\
	"	movq rcu_tasks_trace_srcu_struct+" __stringify(SRCU_srcu_ctrp) "(%rip), %r10\n" \
	"	incq %gs:" __stringify(SRCU_CTR_srcu_locks) "(%r10)\n"			\
	"	movq %r10, " __stringify(TASK_trc_reader_scp) "(%r11)\n"		\
	TRACE_RCU_MB								\
	"771:\n"

#define TRACE_RCU_READ_UNLOCK							\
	"	movq %gs:current_task(%rip), %r11\n"					\
	"	movl " __stringify(TASK_trc_reader_nesting) "(%r11), %r10d\n"		\
	"	subl $1, %r10d\n"							\
	"	jnz 772f\n"								\
	"	movq " __stringify(TASK_trc_reader_scp) "(%r11), %r10\n"		\
	"	movl $0, " __stringify(TASK_trc_reader_nesting) "(%r11)\n"		\
	TRACE_RCU_MB								\
	"	incq %gs:" __stringify(SRCU_CTR_srcu_unlocks) "(%r10)\n"		\
	"	jmp 773f\n"								\
	"772:	movl %r10d, " __stringify(TASK_trc_reader_nesting) "(%r11)\n"	\
	"773:\n"

#elif defined(CONFIG_TASKS_RCU_TRAMPOLINE_READERS) && defined(CONFIG_ARM64)

#include <asm/alternative-macros.h>
#include <asm/cpucaps.h>
/* arm64's asm-offsets.h redefines TRAMP_VALIAS from <asm/fixmap.h>. */
#pragma push_macro("TRAMP_VALIAS")
#undef TRAMP_VALIAS
#include <asm/asm-offsets.h>
#pragma pop_macro("TRAMP_VALIAS")

#ifndef CONFIG_TASKS_TRACE_RCU_NO_MB
#define TRACE_RCU_MB	"	dmb	ish\n"
#else
#define TRACE_RCU_MB
#endif

#define TRACE_RCU_SRCU_CTRP	"rcu_tasks_trace_srcu_struct+" __stringify(SRCU_SRCU_CTRP)

/* x14 = this CPU's offset; then atomically increment the long at x14 + \areg */
#define TRACE_RCU_PERCPU_INC(areg)						\
	ALTERNATIVE("	mrs	x14, tpidr_el1\n", "	mrs	x14, tpidr_el2\n",		\
		    ARM64_HAS_VIRT_HOST_EXTN)					\
	"	add	x14, x14, " areg "\n"						\
	"778:	ldxr	x15, [x14]\n"							\
	"	add	x15, x15, #1\n"							\
	"	stxr	w16, x15, [x14]\n"						\
	"	cbnz	w16, 778b\n"

#define TRACE_RCU_READ_LOCK							\
	"	mrs	x12, sp_el0\n"							\
	"	ldr	w13, [x12, #" __stringify(TSK_TRC_READER_NESTING) "]\n"	\
	"	add	w14, w13, #1\n"							\
	"	str	w14, [x12, #" __stringify(TSK_TRC_READER_NESTING) "]\n"	\
	"	cbnz	w13, 771f\n"							\
	"	adrp	x13, " TRACE_RCU_SRCU_CTRP "\n"					\
	"	ldr	x13, [x13, #:lo12:" TRACE_RCU_SRCU_CTRP "]\n"			\
	"	str	x13, [x12, #" __stringify(TSK_TRC_READER_SCP) "]\n"		\
	"	add	x13, x13, #" __stringify(SRCU_CTR_SRCU_LOCKS) "\n"		\
	TRACE_RCU_PERCPU_INC("x13")						\
	TRACE_RCU_MB								\
	"771:\n"

#define TRACE_RCU_READ_UNLOCK							\
	"	mrs	x12, sp_el0\n"							\
	"	ldr	w13, [x12, #" __stringify(TSK_TRC_READER_NESTING) "]\n"	\
	"	subs	w13, w13, #1\n"							\
	"	b.ne	772f\n"								\
	"	ldr	x13, [x12, #" __stringify(TSK_TRC_READER_SCP) "]\n"		\
	"	str	wzr, [x12, #" __stringify(TSK_TRC_READER_NESTING) "]\n"	\
	TRACE_RCU_MB								\
	"	add	x13, x13, #" __stringify(SRCU_CTR_SRCU_UNLOCKS) "\n"		\
	TRACE_RCU_PERCPU_INC("x13")						\
	"	b	773f\n"								\
	"772:	str	w13, [x12, #" __stringify(TSK_TRC_READER_NESTING) "]\n"	\
	"773:\n"

#else

#define TRACE_RCU_READ_LOCK
#define TRACE_RCU_READ_UNLOCK

#endif

#endif /* _SAMPLES_FTRACE_DIRECT_H */
