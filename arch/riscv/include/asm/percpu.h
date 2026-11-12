/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <linux/thread_info.h>

#include <asm/current.h>

#define __my_cpu_offset (((struct thread_info *)current)->pcpu_offset)

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
