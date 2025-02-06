/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RQSPINLOCK_H
#define _ASM_X86_RQSPINLOCK_H

#include <asm/paravirt.h>

#ifdef CONFIG_PARAVIRT
DECLARE_STATIC_KEY_FALSE(virt_spin_lock_key);

#define resilient_virt_spin_lock_enabled resilient_virt_spin_lock_enabled
static __always_inline bool resilient_virt_spin_lock_enabled(void)
{
       return static_branch_likely(&virt_spin_lock_key);
}

struct qspinlock;
extern int resilient_tas_spin_lock(struct qspinlock *lock, u64 timeout);

#define resilient_virt_spin_lock resilient_virt_spin_lock
static inline int resilient_virt_spin_lock(struct qspinlock *lock, u64 timeout)
{
	return resilient_tas_spin_lock(lock, timeout);
}

#endif /* CONFIG_PARAVIRT */

#include <asm-generic/rqspinlock.h>

#endif /* _ASM_X86_RQSPINLOCK_H */
