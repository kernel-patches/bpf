// SPDX-License-Identifier: GPL-2.0-only

#include <linux/vmalloc.h>
#include <linux/mm.h>

static void *__vmalloc_node_range_split(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end,
			unsigned long exclusion_start, unsigned long exclusion_end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller)
{
	void *res = NULL;

	res = __vmalloc_node_range(size, align, start, exclusion_start,
				gfp_mask, prot, vm_flags, node, caller);
	if (!res)
		res = __vmalloc_node_range(size, align, exclusion_end, end,
				gfp_mask, prot, vm_flags, node, caller);

	return res;
}

void *__vmalloc_node(unsigned long size, unsigned long align,
			    gfp_t gfp_mask, unsigned long vm_flags, int node,
			    const void *caller)
{
	return __vmalloc_node_range_split(size, align, VMALLOC_START,
				VMALLOC_END, code_region_start, code_region_end,
				gfp_mask, PAGE_KERNEL, vm_flags, node, caller);
}

void *vmalloc_huge(unsigned long size, gfp_t gfp_mask)
{
	return __vmalloc_node_range_split(size, 1, VMALLOC_START, VMALLOC_END,
				code_region_start, code_region_end,
				gfp_mask, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
				NUMA_NO_NODE, __builtin_return_address(0));
}

void *vmalloc_user(unsigned long size)
{
	return __vmalloc_node_range_split(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
				code_region_start, code_region_end,
				GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
				VM_USERMAP, NUMA_NO_NODE,
				__builtin_return_address(0));
}

void *vmalloc_32_user(unsigned long size)
{
	return __vmalloc_node_range_split(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
				code_region_start, code_region_end,
				GFP_VMALLOC32 | __GFP_ZERO, PAGE_KERNEL,
				VM_USERMAP, NUMA_NO_NODE,
				__builtin_return_address(0));
}

