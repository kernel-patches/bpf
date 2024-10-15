/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */
#ifndef _ASM_COMPILER_H
#define _ASM_COMPILER_H

#ifndef CONFIG_BPF_JIT_ALWAYS_ON
#define arch_prepare_goto() \
	asm volatile(".reloc\t., R_LARCH_NONE, %0" : : "i" (jumptable))
#endif

#endif /* _ASM_COMPILER_H */
