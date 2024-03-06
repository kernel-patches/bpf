// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

void * __weak module_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS,
			NUMA_NO_NODE, __builtin_return_address(0));
}

void __weak module_memfree(void *module_region)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(module_region);
}
