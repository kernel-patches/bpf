// SPDX-License-Identifier: GPL-2.0-only

#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/jitalloc.h>

static struct jit_alloc_params jit_alloc_params;

static void *jit_alloc(size_t len, unsigned int alignment, pgprot_t pgprot,
		       unsigned long start, unsigned long end,
		       unsigned long fallback_start, unsigned long fallback_end,
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
		unsigned long fallback_start = jit_alloc_params.text.fallback_start;
		unsigned long fallback_end = jit_alloc_params.text.fallback_end;
		bool kasan = jit_alloc_params.flags & JIT_ALLOC_KASAN_SHADOW;

		return jit_alloc(len, align, pgprot, start, end,
				 fallback_start, fallback_end, kasan);
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
