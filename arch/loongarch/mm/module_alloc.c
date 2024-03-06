// SPDX-License-Identifier: GPL-2.0+
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

void *module_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
			GFP_KERNEL, PAGE_KERNEL, 0, NUMA_NO_NODE, __builtin_return_address(0));
}
