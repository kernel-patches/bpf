// SPDX-License-Identifier: GPL-2.0-only
#include <linux/vmalloc.h>
#include <linux/elf.h>

#include <asm/module.h>

inline void __init arch_init_checked_vmap_ranges(void)
{
	if (IS_ENABLED(CONFIG_ARM64_FORCE_CODE_PARTITIONING))
		create_vmalloc_range_check(get_modules_base(),
				get_modules_end() + SZ_2G);
}
