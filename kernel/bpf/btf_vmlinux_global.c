// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF global variable information for debugging tools.
 */
#include <linux/btf.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#if IS_BUILTIN(CONFIG_DEBUG_INFO_BTF_GLOBAL)
extern char __start_BTF_global[];
extern char __stop_BTF_global[];
#endif

static int __init btf_vmlinux_global_init(void)
{
#if IS_BUILTIN(CONFIG_DEBUG_INFO_BTF_GLOBAL)
	size_t data_size = __stop_BTF_global - __start_BTF_global;

	if (data_size)
		sysfs_btf_add("vmlinux.global", __start_BTF_global, data_size, true, NULL);
#endif
	return 0;
}
subsys_initcall(btf_vmlinux_global_init);

MODULE_DESCRIPTION("BTF global variable information for vmlinux");
MODULE_LICENSE("GPL");
