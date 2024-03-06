// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>
#include <asm/alternative.h>
#include <asm/sections.h>

#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
void *module_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, MODULES_VADDR,
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
				    NUMA_NO_NODE,
				    __builtin_return_address(0));
}
#endif
