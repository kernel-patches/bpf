/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RQSPINLOCK_H
#define _ASM_RQSPINLOCK_H

#include <asm/barrier.h>

#define res_smp_cond_load_acquire_waiting() arch_timer_evtstrm_available()

#include <asm-generic/rqspinlock.h>

#endif /* _ASM_RQSPINLOCK_H */
