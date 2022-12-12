// SPDX-License-Identifier: GPL-2.0
#include <linux/page_ext.h>
#include <linux/active_vm.h>

static bool __active_vm_enabled __initdata =
				IS_ENABLED(CONFIG_ACTIVE_VM);

DEFINE_STATIC_KEY_TRUE(active_vm_disabled);
EXPORT_SYMBOL(active_vm_disabled);

static int __init early_active_vm_param(char *buf)
{
	return strtobool(buf, &__active_vm_enabled);
}

early_param("active_vm", early_active_vm_param);

static bool __init need_active_vm(void)
{
	return __active_vm_enabled;
}

static void __init init_active_vm(void)
{
	if (!__active_vm_enabled)
		return;

	static_branch_disable(&active_vm_disabled);
}

struct page_ext_operations active_vm_ops = {
	.need = need_active_vm,
	.init = init_active_vm,
};

DEFINE_PER_CPU(int, irq_active_vm_item);
DEFINE_PER_CPU(int, soft_active_vm_item);
EXPORT_PER_CPU_SYMBOL(irq_active_vm_item);
EXPORT_PER_CPU_SYMBOL(soft_active_vm_item);
DEFINE_PER_CPU(struct active_vm_stat, active_vm_stats);
EXPORT_PER_CPU_SYMBOL(active_vm_stats);

long active_vm_item_sum(int item)
{
	struct active_vm_stat *this;
	long sum = 0;
	int cpu;

	WARN_ON_ONCE(item <= 0);
	for_each_online_cpu(cpu) {
		this = &per_cpu(active_vm_stats, cpu);
		sum += this->stat[item - 1];
	}

	return sum;
}
