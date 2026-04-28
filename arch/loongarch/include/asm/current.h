/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_LOONGARCH_CURRENT_H
#define __ASM_LOONGARCH_CURRENT_H

#include <linux/compiler.h>

#ifndef __ASSEMBLER__

struct task_struct;

register struct task_struct *current_thread_pointer __asm__("$tp");

static __always_inline struct task_struct *get_current(void)
{
	return current_thread_pointer;
}

#define current get_current()

#endif /* __ASSEMBLER__ */

#endif /* __ASM_LOONGARCH_CURRENT_H */
