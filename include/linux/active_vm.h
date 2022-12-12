/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INCLUDE_ACTIVE_VM_H
#define __INCLUDE_ACTIVE_VM_H

#ifdef CONFIG_ACTIVE_VM
#include <linux/jump_label.h>

extern struct static_key_true active_vm_disabled;

static inline bool active_vm_enabled(void)
{
	if (static_branch_likely(&active_vm_disabled))
		return false;

	return true;
}
#else
static inline bool active_vm_enabled(void)
{
	return false;
}
#endif /* CONFIG_ACTIVE_VM */
#endif /* __INCLUDE_ACTIVE_VM_H */
