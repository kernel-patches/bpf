/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MODULELOADER_H
#define _LINUX_MODULELOADER_H
/* The stuff needed for archs to support modules. */

#include <linux/module.h>
#include <linux/elf.h>

/* These may be implemented by architectures that need to hook into the
 * module loader code.  Architectures that don't need to do anything special
 * can just rely on the 'weak' default hooks defined in kernel/module.c.
 * Note, however, that at least one of apply_relocate or apply_relocate_add
 * must be implemented by each architecture.
 */

/* arch may override to do additional checking of ELF header architecture */
bool module_elf_check_arch(Elf_Ehdr *hdr);

/* Adjust arch-specific sections.  Return 0 on success.  */
int module_frob_arch_sections(Elf_Ehdr *hdr,
			      Elf_Shdr *sechdrs,
			      char *secstrings,
			      struct module *mod);

/* Additional bytes needed by arch in front of individual sections */
unsigned int arch_mod_section_prepend(struct module *mod, unsigned int section);

/* Allocator used for allocating struct module, core sections and init
   sections.  Returns NULL on failure. */
void *module_alloc(unsigned long size);

/* Free memory returned from module_alloc. */
void module_memfree(void *module_region);

#ifdef CONFIG_MODULES

/* For mod_alloc_params.flags */
enum mod_alloc_params_flags {
	MOD_ALLOC_FALLBACK		= (1 << 0),	/* Fallback to module_alloc() */
	MOD_ALLOC_KASAN_MODULE_SHADOW	= (1 << 1),	/* Calls kasan_alloc_module_shadow() */
	MOD_ALLOC_KASAN_RESET_TAG	= (1 << 2),	/* Calls kasan_reset_tag() */
	MOD_ALLOC_SET_MEMORY		= (1 << 3),	/* The allocator calls set_memory_ on
							 * memory before returning it to the
							 * caller, so that the caller do not need
							 * to call set_memory_* again. This does
							 * not work for MOD_RO_AFTER_INIT.
							 */
};

#define MOD_MAX_ADDR_SPACES 2

/**
 * struct vmalloc_params - Parameters to call __vmalloc_node_range()
 * @start:          Address space range start
 * @end:            Address space range end
 * @gfp_mask:       The gfp_t mask used for this range
 * @pgprot:         The page protection for this range
 * @vm_flags        The vm_flag used for this range
 */
struct vmalloc_params {
	unsigned long	start;
	unsigned long	end;
	gfp_t		gfp_mask;
	pgprot_t	pgprot;
	unsigned long	vm_flags;
};

/**
 * struct mod_alloc_params - Parameters for module allocation type
 * @flags:          Properties in mod_alloc_params_flags
 * @granularity:    The allocation granularity (PAGE/PMD) in bytes
 * @alignment:      The allocation alignment requirement
 * @vmp:            Parameters used to call vmalloc
 * @fill:           Function to fill allocated space. If NULL, use memcpy()
 * @invalidate:     Function to invalidate memory space.
 *
 * If @granularity > @alignment the allocation can reuse free space in
 * previously allocated pages. If they are the same, then fresh pages
 * have to be allocated.
 */
struct mod_alloc_params {
	unsigned int		flags;
	unsigned int		granularity;
	unsigned int		alignment;
	struct vmalloc_params	vmp[MOD_MAX_ADDR_SPACES];
	void *			(*fill)(void *dst, const void *src, size_t len);
	void *			(*invalidate)(void *ptr, size_t len);
};

struct mod_type_allocator {
	struct mod_alloc_params	params;
};

struct mod_allocators {
	struct mod_type_allocator *types[MOD_MEM_NUM_TYPES];
};

void *module_alloc_type(size_t size, enum mod_mem_type type);
void module_memfree_type(void *ptr, enum mod_mem_type type);
void module_memory_fill_type(void *dst, void *src, size_t len, enum mod_mem_type type);
void module_memory_invalidate_type(void *ptr, size_t len, enum mod_mem_type type);
void module_memory_protect(void *ptr, size_t len, enum mod_mem_type type);
void module_memory_unprotect(void *ptr, size_t len, enum mod_mem_type type);
void module_memory_force_protect(void *ptr, size_t len, enum mod_mem_type type);
void module_memory_force_unprotect(void *ptr, size_t len, enum mod_mem_type type);
void module_alloc_type_init(struct mod_allocators *allocators);

#endif /* CONFIG_MODULES */

/* Determines if the section name is an init section (that is only used during
 * module loading).
 */
bool module_init_section(const char *name);

/* Determines if the section name is an exit section (that is only used during
 * module unloading)
 */
bool module_exit_section(const char *name);

/*
 * Apply the given relocation to the (simplified) ELF.  Return -error
 * or 0.
 */
#ifdef CONFIG_MODULES_USE_ELF_REL
int apply_relocate(Elf_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *mod);
#else
static inline int apply_relocate(Elf_Shdr *sechdrs,
				 const char *strtab,
				 unsigned int symindex,
				 unsigned int relsec,
				 struct module *me)
{
	printk(KERN_ERR "module %s: REL relocation unsupported\n",
	       module_name(me));
	return -ENOEXEC;
}
#endif

/*
 * Apply the given add relocation to the (simplified) ELF.  Return
 * -error or 0
 */
#ifdef CONFIG_MODULES_USE_ELF_RELA
int apply_relocate_add(Elf_Shdr *sechdrs,
		       const char *strtab,
		       unsigned int symindex,
		       unsigned int relsec,
		       struct module *mod);
#ifdef CONFIG_LIVEPATCH
/*
 * Some architectures (namely x86_64 and ppc64) perform sanity checks when
 * applying relocations.  If a patched module gets unloaded and then later
 * reloaded (and re-patched), klp re-applies relocations to the replacement
 * function(s).  Any leftover relocations from the previous loading of the
 * patched module might trigger the sanity checks.
 *
 * To prevent that, when unloading a patched module, clear out any relocations
 * that might trigger arch-specific sanity checks on a future module reload.
 */
void clear_relocate_add(Elf_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me);
#endif
#else
static inline int apply_relocate_add(Elf_Shdr *sechdrs,
				     const char *strtab,
				     unsigned int symindex,
				     unsigned int relsec,
				     struct module *me)
{
	printk(KERN_ERR "module %s: REL relocation unsupported\n",
	       module_name(me));
	return -ENOEXEC;
}
#endif

/* Any final processing of module before access.  Return -error or 0. */
int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *mod);

/* Any cleanup needed when module leaves. */
void module_arch_cleanup(struct module *mod);

/* Any cleanup before freeing mod->module_init */
void module_arch_freeing_init(struct module *mod);

#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
		!defined(CONFIG_KASAN_VMALLOC)
#include <linux/kasan.h>
#define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
#else
#define MODULE_ALIGN PAGE_SIZE
#endif

#endif
