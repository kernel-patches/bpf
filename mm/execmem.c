// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>

struct execmem_params execmem_params;

static void *execmem_alloc(size_t len, unsigned long start, unsigned long end,
			   unsigned int alignment, pgprot_t pgprot,
			   unsigned long fallback_start,
			   unsigned long fallback_end,
			   bool kasan)
{
	unsigned long vm_flags  = VM_FLUSH_RESET_PERMS;
	bool fallback  = !!fallback_start;
	gfp_t gfp_flags = GFP_KERNEL;
	void *p;

	if (PAGE_ALIGN(len) > (end - start))
		return NULL;

	if (kasan)
		vm_flags |= VM_DEFER_KMEMLEAK;

	if (fallback)
		gfp_flags |= __GFP_NOWARN;

	p = __vmalloc_node_range(len, alignment, start, end, gfp_flags,
				 pgprot, vm_flags, NUMA_NO_NODE,
				 __builtin_return_address(0));

	if (!p && fallback) {
		start = fallback_start;
		end = fallback_end;
		gfp_flags = GFP_KERNEL;

		p = __vmalloc_node_range(len, alignment, start, end, gfp_flags,
					 pgprot, vm_flags, NUMA_NO_NODE,
					 __builtin_return_address(0));
	}

	if (p && kasan && (kasan_alloc_module_shadow(p, len, GFP_KERNEL) < 0)) {
		vfree(p);
		return NULL;
	}

	return kasan_reset_tag(p);
}

void *execmem_text_alloc(size_t size)
{
	unsigned long start = execmem_params.modules.text.start;
	unsigned long end = execmem_params.modules.text.end;
	pgprot_t pgprot = execmem_params.modules.text.pgprot;
	unsigned int align = execmem_params.modules.text.alignment;
	unsigned long fallback_start = execmem_params.modules.text.fallback_start;
	unsigned long fallback_end = execmem_params.modules.text.fallback_end;
	bool kasan = execmem_params.modules.flags & EXECMEM_KASAN_SHADOW;

	if (!execmem_params.modules.text.start)
		return module_alloc(size);

	return execmem_alloc(size, start, end, align, pgprot,
			     fallback_start, fallback_end, kasan);
}

void execmem_free(void *ptr)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(ptr);
}

void *jit_text_alloc(size_t size)
{
	return execmem_text_alloc(size);
}

void jit_free(void *ptr)
{
	execmem_free(ptr);
}

struct execmem_params * __weak execmem_arch_params(void)
{
	return NULL;
}

static bool execmem_validate_params(struct execmem_params *p)
{
	struct execmem_modules_range *m = &p->modules;
	struct execmem_range *t = &m->text;

	if (!t->alignment || !t->start || !t->end || !pgprot_val(t->pgprot)) {
		pr_crit("Invalid parameters for execmem allocator, module loading will fail");
		return false;
	}

	return true;
}

void __init execmem_init(void)
{
	struct execmem_params *p = execmem_arch_params();

	if (!p)
		return;

	if (!execmem_validate_params(p))
		return;

	execmem_params = *p;
}
