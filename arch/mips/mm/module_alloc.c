// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

#ifdef MODULE_START
void *module_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, MODULE_START, MODULE_END,
				GFP_KERNEL, PAGE_KERNEL, 0, NUMA_NO_NODE,
				__builtin_return_address(0));
}
#endif
