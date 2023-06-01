// SPDX-License-Identifier: GPL-2.0-only

#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/jitalloc.h>

static struct jit_alloc_params jit_alloc_params;

#ifdef CONFIG_ARCH_HAS_TEXT_POKE
#include <asm/text-patching.h>

static inline void jit_text_poke_copy(void *dst, const void *src, size_t len)
{
	if (jit_alloc_params.flags & JIT_ALLOC_USE_TEXT_POKE)
		text_poke_copy(dst, src, len);
	else
		memcpy(dst, src, len);
}

static inline void jit_text_poke_set(void *addr, int c, size_t len)
{
	if (jit_alloc_params.flags & JIT_ALLOC_USE_TEXT_POKE)
		text_poke_set(addr, c, len);
	else
		memset(addr, c, len);
}

#else
static inline void jit_text_poke_copy(void *dst, const void *src, size_t len)
{
	memcpy(dst, src, len);
}

static inline void jit_text_poke_set(void *addr, int c, size_t len)
{
	memset(addr, c, len);
}
#endif

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

void *jit_data_alloc(size_t len)
{
	unsigned int align = jit_alloc_params.alignment;
	pgprot_t pgprot = jit_alloc_params.data.pgprot;
	unsigned long start = jit_alloc_params.data.start;
	unsigned long end = jit_alloc_params.data.end;
	unsigned long fallback_start = jit_alloc_params.data.fallback_start;
	unsigned long fallback_end = jit_alloc_params.data.fallback_end;
	bool kasan = jit_alloc_params.flags & JIT_ALLOC_KASAN_SHADOW;

	return jit_alloc(len, align, pgprot, start, end,
			 fallback_start, fallback_end, kasan);
}

void jit_update_copy(void *buf, void *new_buf, size_t len)
{
	jit_text_poke_copy(buf, new_buf, len);
}

void jit_update_set(void *addr, int c, size_t len)
{
	jit_text_poke_set(addr, c, len);
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

static void jit_alloc_init_missing(struct jit_alloc_params *p)
{
	if (!pgprot_val(jit_alloc_params.data.pgprot))
		jit_alloc_params.data.pgprot = PAGE_KERNEL;

	if (!jit_alloc_params.data.start) {
		jit_alloc_params.data.start = p->text.start;
		jit_alloc_params.data.end = p->text.end;
	}

	if (!jit_alloc_params.data.fallback_start &&
	    jit_alloc_params.text.fallback_start) {
		jit_alloc_params.data.fallback_start = p->text.fallback_start;
		jit_alloc_params.data.fallback_end = p->text.fallback_end;
	}
}

void jit_alloc_init(void)
{
	struct jit_alloc_params *p = jit_alloc_arch_params();

	if (p) {
		if (!jit_alloc_validate_params(p))
			return;

		jit_alloc_params = *p;
		jit_alloc_init_missing(p);

		return;
	}

	/* defaults for architecures that don't need special handling */
	jit_alloc_params.alignment	= 1;
	jit_alloc_params.text.pgprot	= PAGE_KERNEL_EXEC;
	jit_alloc_params.text.start	= VMALLOC_START;
	jit_alloc_params.text.end	= VMALLOC_END;
	jit_alloc_params.data.pgprot	= PAGE_KERNEL;
	jit_alloc_params.data.start	= VMALLOC_START;
	jit_alloc_params.data.end	= VMALLOC_END;
}
