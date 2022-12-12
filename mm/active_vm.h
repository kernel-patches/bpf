/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_ACTIVE_VM_H
#define __MM_ACTIVE_VM_H

#ifdef CONFIG_ACTIVE_VM
#include <linux/active_vm.h>

extern struct page_ext_operations active_vm_ops;

static inline int active_vm_item(void)
{
	if (in_irq())
		return this_cpu_read(irq_active_vm_item);

	if (in_softirq())
		return this_cpu_read(soft_active_vm_item);

	return current->active_vm_item;
}

static inline void active_vm_item_add(int item, long delta)
{
	WARN_ON_ONCE(item <= 0);
	this_cpu_add(active_vm_stats.stat[item - 1], delta);
}

static inline void active_vm_item_sub(int item, long delta)
{
	WARN_ON_ONCE(item <= 0);
	this_cpu_sub(active_vm_stats.stat[item - 1], delta);
}
#else /* CONFIG_ACTIVE_VM */
static inline int active_vm_item(void)
{
	return 0;
}

static inline void active_vm_item_add(int item, long delta)
{
}

static inline void active_vm_item_sub(int item, long delta)
{
}
#endif /* CONFIG_ACTIVE_VM */
#endif /* __MM_ACTIVE_VM_H */
