/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/interrupt_rc.h - refcounted local processor interrupt
 * management.
 *
 * Since the implementation of this API currently depends on
 * local_irq_save()/local_irq_restore(), we split this into it's own header to
 * make it easier to include without hitting circular header dependencies.
 */

#ifndef __LINUX_INTERRUPT_RC_H
#define __LINUX_INTERRUPT_RC_H

#include <linux/irqflags.h>
#include <asm/processor.h>
#ifdef CONFIG_SMP
#include <asm/smp.h>
#endif

/* Per-cpu interrupt disabling state for local_interrupt_{disable,enable}() */
struct interrupt_disable_state {
	unsigned long flags;
};

DECLARE_PER_CPU(struct interrupt_disable_state, local_interrupt_disable_state);

static inline void local_interrupt_disable(void)
{
	unsigned long flags;
	int new_count;

	new_count = hardirq_disable_enter();

	/* Interrupts can happen here, but it's OK, see __irq_exit_rcu(). */

	if ((new_count & HARDIRQ_DISABLE_MASK) == HARDIRQ_DISABLE_OFFSET) {
		local_irq_save(flags);
		raw_cpu_write(local_interrupt_disable_state.flags, flags);
	}
}

static inline void local_interrupt_enable(void)
{
	int new_count;

	new_count = hardirq_disable_exit();

	if ((new_count & HARDIRQ_DISABLE_MASK) == 0) {
		unsigned long flags;

		flags = raw_cpu_read(local_interrupt_disable_state.flags);
		local_irq_restore(flags);
		/*
		 * TODO: re-read preempt count can be avoided, but it needs
		 * should_resched() taking another parameter as the current
		 * preempt count
		 */
#ifdef CONFIG_PREEMPTION
		if (should_resched(0))
			__preempt_schedule();
#endif
	}
}

#endif /* !__LINUX_INTERRUPT_RC_H */
