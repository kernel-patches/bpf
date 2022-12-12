// SPDX-License-Identifier: GPL-2.0
#include <linux/page_ext.h>

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
