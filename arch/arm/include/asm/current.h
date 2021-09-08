/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright © 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Author Keith Packard <keithpac@amazon.com>
 */

#ifndef _ASM_ARM_CURRENT_H_
#define _ASM_ARM_CURRENT_H_

#ifndef __ASSEMBLY__

register unsigned long current_stack_pointer asm ("sp");

/*
 * Same as asm-generic/current.h, except that we store current
 * in TPIDRPRW. TPIDRPRW only exists on V6K and V7
 */
#ifdef CONFIG_CURRENT_POINTER_IN_TPIDRPRW

struct task_struct;

static inline void set_current(struct task_struct *tsk)
{
	/* Set TPIDRPRW */
	asm volatile("mcr p15, 0, %0, c13, c0, 4" : : "r" (tsk) : "memory");
}

static __always_inline struct task_struct *get_current(void)
{
	struct task_struct *tsk;

	/*
	 * Read TPIDRPRW.
	 * We want to allow caching the value, so avoid using volatile and
	 * instead use a fake stack read to hazard against barrier().
	 */
	asm("mrc p15, 0, %0, c13, c0, 4" : "=r" (tsk)
		: "Q" (*(const unsigned long *)current_stack_pointer));

	return tsk;
}
#define current get_current()
#else

#define set_current(tsk) do {} while (0)

#include <asm-generic/current.h>

#endif /* CONFIG_SMP */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_ARM_CURRENT_H_ */
