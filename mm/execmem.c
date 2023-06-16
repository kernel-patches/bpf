// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>

struct execmem_params execmem_params;

static void *execmem_alloc(size_t size, unsigned long start, unsigned long end,
			   unsigned int align, pgprot_t pgprot)
{
	return __vmalloc_node_range(size, align, start, end,
				   GFP_KERNEL, pgprot, VM_FLUSH_RESET_PERMS,
				   NUMA_NO_NODE, __builtin_return_address(0));
}

void *execmem_text_alloc(size_t size)
{
	unsigned long start = execmem_params.modules.text.start;
	unsigned long end = execmem_params.modules.text.end;
	pgprot_t pgprot = execmem_params.modules.text.pgprot;
	unsigned int align = execmem_params.modules.text.alignment;

	if (!execmem_params.modules.text.start)
		return module_alloc(size);

	return execmem_alloc(size, start, end, align, pgprot);
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
