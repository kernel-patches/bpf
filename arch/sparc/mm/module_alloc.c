// SPDX-License-Identifier: GPL-2.0
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

#ifdef CONFIG_SPARC64
static void *module_map(unsigned long size)
{
	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;
	return __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
				GFP_KERNEL, PAGE_KERNEL, 0, NUMA_NO_NODE,
				__builtin_return_address(0));
}
#else
static void *module_map(unsigned long size)
{
	return vmalloc(size);
}
#endif /* CONFIG_SPARC64 */

void *module_alloc(unsigned long size)
{
	void *ret;

	ret = module_map(size);
	if (ret)
		memset(ret, 0, size);

	return ret;
}
