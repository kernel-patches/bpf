// SPDX-License-Identifier: GPL-2.0
/*
 * Carrier module for the vmlinux BTF when CONFIG_DEBUG_INFO_BTF=m.
 *
 * This module has no code of its own.  Its .BTF section is a copy of the
 * vmlinux BTF (see scripts/gen-btf.sh), which the BTF module notifier in
 * kernel/bpf/btf.c recognizes by module name and installs as the vmlinux BTF.
 * The kernel loads it on demand, the first time the vmlinux BTF is needed.
 *
 * There is deliberately no module_exit(): once the BTF is in use it cannot
 * be taken away again, exactly as with CONFIG_DEBUG_INFO_BTF=y.
 */
#include <linux/init.h>
#include <linux/module.h>

static int __init btf_vmlinux_init(void)
{
	return 0;
}
module_init(btf_vmlinux_init);

MODULE_DESCRIPTION("BTF type information for vmlinux");
MODULE_LICENSE("GPL");
