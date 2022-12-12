/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INCLUDE_ACTIVE_VM_H
#define __INCLUDE_ACTIVE_VM_H

enum active_vm_item {
	ACTIVE_VM_BPF = 1,
	NR_ACTIVE_VM_ITEM = ACTIVE_VM_BPF,
};

#ifdef CONFIG_ACTIVE_VM
#include <linux/jump_label.h>
#include <linux/preempt.h>
#include <linux/percpu-defs.h>
#include <linux/sched.h>

extern struct static_key_true active_vm_disabled;

static inline bool active_vm_enabled(void)
{
	if (static_branch_likely(&active_vm_disabled))
		return false;

	return true;
}

struct active_vm_stat {
	long stat[NR_ACTIVE_VM_ITEM];
};

DECLARE_PER_CPU(struct active_vm_stat, active_vm_stats);
DECLARE_PER_CPU(int, irq_active_vm_item);
DECLARE_PER_CPU(int, soft_active_vm_item);

static inline int
active_vm_item_set(int item)
{
	int old_item;

	if (in_irq()) {
		old_item = this_cpu_read(irq_active_vm_item);
		this_cpu_write(irq_active_vm_item, item);
	} else if (in_softirq()) {
		old_item = this_cpu_read(soft_active_vm_item);
		this_cpu_write(soft_active_vm_item, item);
	} else {
		old_item = current->active_vm_item;
		current->active_vm_item = item;
	}

	return old_item;
}

long active_vm_item_sum(int item);

#else
static inline bool active_vm_enabled(void)
{
	return false;
}

static inline int
active_vm_item_set(int item)
{
	return 0;
}

static inline long active_vm_item_sum(int item)
{
	return 0;
}

#endif /* CONFIG_ACTIVE_VM */
#endif /* __INCLUDE_ACTIVE_VM_H */
