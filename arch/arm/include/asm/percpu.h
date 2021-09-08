/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2012 Calxeda, Inc.
 */
#ifndef _ASM_ARM_PERCPU_H_
#define _ASM_ARM_PERCPU_H_

register unsigned long current_stack_pointer asm ("sp");

#include <asm-generic/percpu.h>

#endif /* _ASM_ARM_PERCPU_H_ */
