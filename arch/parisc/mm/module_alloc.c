// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

void *module_alloc(unsigned long size)
{
	/* using RWX means less protection for modules, but it's
	 * easier than trying to map the text, data, init_text and
	 * init_data correctly */
	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
				    GFP_KERNEL,
				    PAGE_KERNEL_RWX, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}
