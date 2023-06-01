// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/jitalloc.h>

static struct jit_alloc_params jit_alloc_params = {
	.alignment	= 1,
#ifdef CONFIG_SPARC64
	.text.start	= MODULES_VADDR,
	.text.end	= MODULES_END,
#else
	.text.start	= VMALLOC_START,
	.text.end	= VMALLOC_END,
#endif
};

struct jit_alloc_params *jit_alloc_arch_params(void)
{
	jit_alloc_params.text.pgprot = PAGE_KERNEL;

	return &jit_alloc_params;
}
