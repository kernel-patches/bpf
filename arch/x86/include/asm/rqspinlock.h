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

#endif /* CONFIG_PARAVIRT */

#include <asm-generic/rqspinlock.h>

#endif /* _ASM_X86_RQSPINLOCK_H */
