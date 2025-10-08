/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2015-2016, SUSE, IBM Corp.
 */
#ifndef _ASM_POWERPC_LIVEPATCH_H
#define _ASM_POWERPC_LIVEPATCH_H

#ifdef CONFIG_LIVEPATCH_64
#define LIVEPATCH_STACK_MAGIC_OFFSET	8
#define LIVEPATCH_STACK_LR_OFFSET	16
#define LIVEPATCH_STACK_TOC_OFFSET	24

#if defined(CONFIG_PPC_FTRACE_OUT_OF_LINE) && defined(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)
#define LIVEPATCH_STACK_FRAME_SIZE	32	/* Allocate 4 x 8 bytes (to save new NIP as well) */
#define LIVEPATCH_STACK_NIP_OFFSET	32
#else
#define LIVEPATCH_STACK_FRAME_SIZE	24	/* Allocate 3 x 8 bytes */
#endif
#endif

#ifndef __ASSEMBLY__
#include <linux/sched.h>
#include <linux/sched/task_stack.h>

#ifdef CONFIG_LIVEPATCH_64
static inline void klp_init_thread_info(struct task_struct *p)
{
	/* + 1 to account for STACK_END_MAGIC */
	task_thread_info(p)->livepatch_sp = end_of_stack(p) + 1;
}
#else
static inline void klp_init_thread_info(struct task_struct *p) { }
#endif

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_POWERPC_LIVEPATCH_H */
