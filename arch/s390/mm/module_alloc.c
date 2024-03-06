// SPDX-License-Identifier: GPL-2.0+
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kasan.h>

static unsigned long get_module_load_offset(void)
{
	static DEFINE_MUTEX(module_kaslr_mutex);
	static unsigned long module_load_offset;

	if (!kaslr_enabled())
		return 0;
	/*
	 * Calculate the module_load_offset the first time this code
	 * is called. Once calculated it stays the same until reboot.
	 */
	mutex_lock(&module_kaslr_mutex);
	if (!module_load_offset)
		module_load_offset = get_random_u32_inclusive(1, 1024) * PAGE_SIZE;
	mutex_unlock(&module_kaslr_mutex);
	return module_load_offset;
}

void *module_alloc(unsigned long size)
{
	gfp_t gfp_mask = GFP_KERNEL;
	void *p;

	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;
	p = __vmalloc_node_range(size, MODULE_ALIGN,
				 MODULES_VADDR + get_module_load_offset(),
				 MODULES_END, gfp_mask, PAGE_KERNEL,
				 VM_FLUSH_RESET_PERMS | VM_DEFER_KMEMLEAK,
				 NUMA_NO_NODE, __builtin_return_address(0));
	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
		vfree(p);
		return NULL;
	}
	return p;
}
