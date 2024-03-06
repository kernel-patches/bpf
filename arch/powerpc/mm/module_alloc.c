// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

static __always_inline void *
__module_alloc(unsigned long size, unsigned long start, unsigned long end, bool nowarn)
{
	pgprot_t prot = strict_module_rwx_enabled() ? PAGE_KERNEL : PAGE_KERNEL_EXEC;
	gfp_t gfp = GFP_KERNEL | (nowarn ? __GFP_NOWARN : 0);

	/*
	 * Don't do huge page allocations for modules yet until more testing
	 * is done. STRICT_MODULE_RWX may require extra work to support this
	 * too.
	 */
	return __vmalloc_node_range(size, 1, start, end, gfp, prot,
				    VM_FLUSH_RESET_PERMS,
				    NUMA_NO_NODE, __builtin_return_address(0));
}

void *module_alloc(unsigned long size)
{
#ifdef MODULES_VADDR
	unsigned long limit = (unsigned long)_etext - SZ_32M;
	void *ptr = NULL;

	BUILD_BUG_ON(TASK_SIZE > MODULES_VADDR);

	/* First try within 32M limit from _etext to avoid branch trampolines */
	if (MODULES_VADDR < PAGE_OFFSET && MODULES_END > limit)
		ptr = __module_alloc(size, limit, MODULES_END, true);

	if (!ptr)
		ptr = __module_alloc(size, MODULES_VADDR, MODULES_END, false);

	return ptr;
#else
	return __module_alloc(size, VMALLOC_START, VMALLOC_END, false);
#endif
}
