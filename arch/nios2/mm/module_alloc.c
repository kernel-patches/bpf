// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/moduleloader.h>
#include <linux/slab.h>

/*
 * Modules should NOT be allocated with kmalloc for (obvious) reasons.
 * But we do it for now to avoid relocation issues. CALL26/PCREL26 cannot reach
 * from 0x80000000 (vmalloc area) to 0xc00000000 (kernel) (kmalloc returns
 * addresses in 0xc0000000)
 */
void *module_alloc(unsigned long size)
{
	if (size == 0)
		return NULL;
	return kmalloc(size, GFP_KERNEL);
}

/* Free memory returned from module_alloc */
void module_memfree(void *module_region)
{
	kfree(module_region);
}
