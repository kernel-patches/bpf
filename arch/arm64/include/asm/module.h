/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_MODULE_H
#define __ASM_MODULE_H

#include <asm-generic/module.h>

struct mod_plt_sec {
	int			plt_shndx;
	int			plt_num_entries;
	int			plt_max_entries;
};

struct mod_dwarf_cfi_index;

struct mod_arch_specific {
	struct mod_plt_sec	core;
	struct mod_plt_sec	init;

	/* for CONFIG_DYNAMIC_FTRACE */
	struct plt_entry	*ftrace_trampolines;
	struct plt_entry	*init_ftrace_trampolines;

#ifdef CONFIG_UNWINDER_DWARF_CFI
	struct mod_dwarf_cfi_index __rcu *dwarf_cfi_index;
#endif
};

#ifdef CONFIG_UNWINDER_DWARF_CFI
void arm64_unwind_module_init(struct module *mod, void *eh_frame,
			      size_t eh_frame_size);
void arm64_unwind_module_cleanup(struct module *mod);
#else
static inline void arm64_unwind_module_init(struct module *mod, void *eh_frame,
					    size_t eh_frame_size) {}
static inline void arm64_unwind_module_cleanup(struct module *mod) {}
#endif

u64 module_emit_plt_entry(struct module *mod, Elf64_Shdr *sechdrs,
			  void *loc, const Elf64_Rela *rela,
			  Elf64_Sym *sym);

u64 module_emit_veneer_for_adrp(struct module *mod, Elf64_Shdr *sechdrs,
				void *loc, u64 val);

struct plt_entry {
	/*
	 * A program that conforms to the AArch64 Procedure Call Standard
	 * (AAPCS64) must assume that a veneer that alters IP0 (x16) and/or
	 * IP1 (x17) may be inserted at any branch instruction that is
	 * exposed to a relocation that supports long branches. Since that
	 * is exactly what we are dealing with here, we are free to use x16
	 * as a scratch register in the PLT veneers.
	 */
	__le32	adrp;	/* adrp	x16, ....			*/
	__le32	add;	/* add	x16, x16, #0x....		*/
	__le32	br;	/* br	x16				*/
};

static inline bool is_forbidden_offset_for_adrp(void *place)
{
	return cpus_have_final_cap(ARM64_WORKAROUND_843419) &&
	       ((u64)place & 0xfff) >= 0xff8;
}

struct plt_entry get_plt_entry(u64 dst, void *pc);

static inline const Elf_Shdr *find_section(const Elf_Ehdr *hdr,
				    const Elf_Shdr *sechdrs,
				    const char *name)
{
	const Elf_Shdr *s, *se;
	const char *secstrs = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (s = sechdrs, se = sechdrs + hdr->e_shnum; s < se; s++) {
		if (strcmp(name, secstrs + s->sh_name) == 0)
			return s;
	}

	return NULL;
}

#endif /* __ASM_MODULE_H */
