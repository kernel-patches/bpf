// SPDX-License-Identifier: GPL-2.0-only

#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/jitalloc.h>

static struct jit_alloc_params jit_alloc_params;

static void *jit_alloc(size_t len, unsigned int alignment, pgprot_t pgprot,
		       unsigned long start, unsigned long end)
{
	if (PAGE_ALIGN(len) > (end - start))
		return NULL;

	return __vmalloc_node_range(len, alignment, start, end, GFP_KERNEL,
				    pgprot, VM_FLUSH_RESET_PERMS,
				    NUMA_NO_NODE, __builtin_return_address(0));
}

void jit_free(void *buf)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(buf);
}

void *jit_text_alloc(size_t len)
{
	if (jit_alloc_params.text.start) {
		unsigned int align = jit_alloc_params.alignment;
		pgprot_t pgprot = jit_alloc_params.text.pgprot;
		unsigned long start = jit_alloc_params.text.start;
		unsigned long end = jit_alloc_params.text.end;

		return jit_alloc(len, align, pgprot, start, end);
	}

	return module_alloc(len);
}

struct jit_alloc_params * __weak jit_alloc_arch_params(void)
{
	return NULL;
}

static bool jit_alloc_validate_params(struct jit_alloc_params *p)
{
	if (!p->alignment || !p->text.start || !p->text.end ||
	    !pgprot_val(p->text.pgprot)) {
		pr_crit("Invalid parameters for jit allocator, module loading will fail");
		return false;
	}

	return true;
}

void jit_alloc_init(void)
{
	struct jit_alloc_params *p = jit_alloc_arch_params();

	if (p) {
		if (!jit_alloc_validate_params(p))
			return;

		jit_alloc_params = *p;
	}
}
