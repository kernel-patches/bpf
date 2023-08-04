// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  Copyright (C) 2017 Zihao Yu
 */

#include <linux/elf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/sizes.h>
#include <linux/pgtable.h>
#include <asm/alternative.h>
#include <asm/insn.h>
#include <asm/sections.h>

#define HI20_OFFSET 0x800

/*
 * The auipc+jalr instruction pair can reach any PC-relative offset
 * in the range [-2^31 - 2^11, 2^31 - 2^11)
 */
static bool riscv_insn_valid_32bit_offset(ptrdiff_t val)
{
#ifdef CONFIG_32BIT
	return true;
#else
	return (-(1L << 31) - (1L << 11)) <= val && val < ((1L << 31) - (1L << 11));
#endif
}

static int apply_r_riscv_32_rela(struct module *me, u32 *location, Elf_Addr v)
{
	if (v != (u32)v) {
		pr_err("%s: value %016llx out of range for 32-bit field\n",
		       me->name, (long long)v);
		return -EINVAL;
	}
	*location = v;
	return 0;
}

static int apply_r_riscv_64_rela(struct module *me, u32 *location, Elf_Addr v)
{
	*(u64 *)location = v;
	return 0;
}

static int apply_r_riscv_branch_rela(struct module *me, u32 *location,
				     Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	riscv_insn_insert_btype_imm(location, ((s32)offset));
	return 0;
}

static int apply_r_riscv_jal_rela(struct module *me, u32 *location,
				  Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	riscv_insn_insert_jtype_imm(location, ((s32)offset));
	return 0;
}

static int apply_r_riscv_rvc_branch_rela(struct module *me, u32 *location,
					 Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	riscv_insn_insert_cbztype_imm(location, (s32)offset);
	return 0;
}

static int apply_r_riscv_rvc_jump_rela(struct module *me, u32 *location,
				       Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	riscv_insn_insert_cjtype_imm(location, (s32)offset);
	return 0;
}

static int apply_r_riscv_pcrel_hi20_rela(struct module *me, u32 *location,
					 Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	if (!riscv_insn_valid_32bit_offset(offset)) {
		pr_err(
		  "%s: target %016llx can not be addressed by the 32-bit offset from PC = %p\n",
		  me->name, (long long)v, location);
		return -EINVAL;
	}

	riscv_insn_insert_utype_imm(location, (offset + HI20_OFFSET));
	return 0;
}

static int apply_r_riscv_pcrel_lo12_i_rela(struct module *me, u32 *location,
					   Elf_Addr v)
{
	/*
	 * v is the lo12 value to fill. It is calculated before calling this
	 * handler.
	 */
	riscv_insn_insert_itype_imm(location, ((s32)v));
	return 0;
}

static int apply_r_riscv_pcrel_lo12_s_rela(struct module *me, u32 *location,
					   Elf_Addr v)
{
	/*
	 * v is the lo12 value to fill. It is calculated before calling this
	 * handler.
	 */
	riscv_insn_insert_stype_imm(location, ((s32)v));
	return 0;
}

static int apply_r_riscv_hi20_rela(struct module *me, u32 *location,
				   Elf_Addr v)
{
	if (IS_ENABLED(CONFIG_CMODEL_MEDLOW)) {
		pr_err(
		  "%s: target %016llx can not be addressed by the 32-bit offset from PC = %p\n",
		  me->name, (long long)v, location);
		return -EINVAL;
	}

	riscv_insn_insert_utype_imm(location, ((s32)v + HI20_OFFSET));
	return 0;
}

static int apply_r_riscv_lo12_i_rela(struct module *me, u32 *location,
				     Elf_Addr v)
{
	/* Skip medlow checking because of filtering by HI20 already */
	riscv_insn_insert_itype_imm(location, (s32)v);
	return 0;
}

static int apply_r_riscv_lo12_s_rela(struct module *me, u32 *location,
				     Elf_Addr v)
{
	/* Skip medlow checking because of filtering by HI20 already */
	riscv_insn_insert_stype_imm(location, (s32)v);
	return 0;
}

static int apply_r_riscv_got_hi20_rela(struct module *me, u32 *location,
				       Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	/* Always emit the got entry */
	if (IS_ENABLED(CONFIG_MODULE_SECTIONS)) {
		offset = module_emit_got_entry(me, v);
		offset = (void *)offset - (void *)location;
	} else {
		pr_err(
		  "%s: can not generate the GOT entry for symbol = %016llx from PC = %p\n",
		  me->name, (long long)v, location);
		return -EINVAL;
	}

	riscv_insn_insert_utype_imm(location, (s32)(offset + HI20_OFFSET));
	return 0;
}

static int apply_r_riscv_call_plt_rela(struct module *me, u32 *location,
				       Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	if (!riscv_insn_valid_32bit_offset(offset)) {
		/* Only emit the plt entry if offset over 32-bit range */
		if (IS_ENABLED(CONFIG_MODULE_SECTIONS)) {
			offset = module_emit_plt_entry(me, v);
			offset = (void *)offset - (void *)location;
		} else {
			pr_err(
			  "%s: target %016llx can not be addressed by the 32-bit offset from PC = %p\n",
			  me->name, (long long)v, location);
			return -EINVAL;
		}
	}

	riscv_insn_insert_utype_itype_imm(location, location + 1, (s32)offset);
	return 0;
}

static int apply_r_riscv_call_rela(struct module *me, u32 *location,
				   Elf_Addr v)
{
	ptrdiff_t offset = (void *)v - (void *)location;

	if (!riscv_insn_valid_32bit_offset(offset)) {
		pr_err(
		  "%s: target %016llx can not be addressed by the 32-bit offset from PC = %p\n",
		  me->name, (long long)v, location);
		return -EINVAL;
	}

	riscv_insn_insert_utype_itype_imm(location, location + 1, (s32)offset);
	return 0;
}

static int apply_r_riscv_relax_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	return 0;
}

static int apply_r_riscv_align_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	pr_err(
	  "%s: The unexpected relocation type 'R_RISCV_ALIGN' from PC = %p\n",
	  me->name, location);
	return -EINVAL;
}

static int apply_r_riscv_add16_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	*(u16 *)location += (u16)v;
	return 0;
}

static int apply_r_riscv_add32_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	*(u32 *)location += (u32)v;
	return 0;
}

static int apply_r_riscv_add64_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	*(u64 *)location += (u64)v;
	return 0;
}

static int apply_r_riscv_sub16_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	*(u16 *)location -= (u16)v;
	return 0;
}

static int apply_r_riscv_sub32_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	*(u32 *)location -= (u32)v;
	return 0;
}

static int apply_r_riscv_sub64_rela(struct module *me, u32 *location,
				    Elf_Addr v)
{
	*(u64 *)location -= (u64)v;
	return 0;
}

static int (*reloc_handlers_rela[]) (struct module *me, u32 *location,
				Elf_Addr v) = {
	[R_RISCV_32]			= apply_r_riscv_32_rela,
	[R_RISCV_64]			= apply_r_riscv_64_rela,
	[R_RISCV_BRANCH]		= apply_r_riscv_branch_rela,
	[R_RISCV_JAL]			= apply_r_riscv_jal_rela,
	[R_RISCV_RVC_BRANCH]		= apply_r_riscv_rvc_branch_rela,
	[R_RISCV_RVC_JUMP]		= apply_r_riscv_rvc_jump_rela,
	[R_RISCV_PCREL_HI20]		= apply_r_riscv_pcrel_hi20_rela,
	[R_RISCV_PCREL_LO12_I]		= apply_r_riscv_pcrel_lo12_i_rela,
	[R_RISCV_PCREL_LO12_S]		= apply_r_riscv_pcrel_lo12_s_rela,
	[R_RISCV_HI20]			= apply_r_riscv_hi20_rela,
	[R_RISCV_LO12_I]		= apply_r_riscv_lo12_i_rela,
	[R_RISCV_LO12_S]		= apply_r_riscv_lo12_s_rela,
	[R_RISCV_GOT_HI20]		= apply_r_riscv_got_hi20_rela,
	[R_RISCV_CALL_PLT]		= apply_r_riscv_call_plt_rela,
	[R_RISCV_CALL]			= apply_r_riscv_call_rela,
	[R_RISCV_RELAX]			= apply_r_riscv_relax_rela,
	[R_RISCV_ALIGN]			= apply_r_riscv_align_rela,
	[R_RISCV_ADD16]			= apply_r_riscv_add16_rela,
	[R_RISCV_ADD32]			= apply_r_riscv_add32_rela,
	[R_RISCV_ADD64]			= apply_r_riscv_add64_rela,
	[R_RISCV_SUB16]			= apply_r_riscv_sub16_rela,
	[R_RISCV_SUB32]			= apply_r_riscv_sub32_rela,
	[R_RISCV_SUB64]			= apply_r_riscv_sub64_rela,
};

int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab,
		       unsigned int symindex, unsigned int relsec,
		       struct module *me)
{
	Elf_Rela *rel = (void *) sechdrs[relsec].sh_addr;
	int (*handler)(struct module *me, u32 *location, Elf_Addr v);
	Elf_Sym *sym;
	u32 *location;
	unsigned int i, type;
	Elf_Addr v;
	int res;

	pr_debug("Applying relocate section %u to %u\n", relsec,
	       sechdrs[relsec].sh_info);

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		location = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;
		/* This is the symbol it is referring to */
		sym = (Elf_Sym *)sechdrs[symindex].sh_addr
			+ ELF_RISCV_R_SYM(rel[i].r_info);
		if (IS_ERR_VALUE(sym->st_value)) {
			/* Ignore unresolved weak symbol */
			if (ELF_ST_BIND(sym->st_info) == STB_WEAK)
				continue;
			pr_warn("%s: Unknown symbol %s\n",
				me->name, strtab + sym->st_name);
			return -ENOENT;
		}

		type = ELF_RISCV_R_TYPE(rel[i].r_info);

		if (type < ARRAY_SIZE(reloc_handlers_rela))
			handler = reloc_handlers_rela[type];
		else
			handler = NULL;

		if (!handler) {
			pr_err("%s: Unknown relocation type %u\n",
			       me->name, type);
			return -EINVAL;
		}

		v = sym->st_value + rel[i].r_addend;

		if (type == R_RISCV_PCREL_LO12_I || type == R_RISCV_PCREL_LO12_S) {
			unsigned int j;

			for (j = 0; j < sechdrs[relsec].sh_size / sizeof(*rel); j++) {
				unsigned long hi20_loc =
					sechdrs[sechdrs[relsec].sh_info].sh_addr
					+ rel[j].r_offset;
				u32 hi20_type = ELF_RISCV_R_TYPE(rel[j].r_info);

				/* Find the corresponding HI20 relocation entry */
				if (hi20_loc == sym->st_value
				    && (hi20_type == R_RISCV_PCREL_HI20
					|| hi20_type == R_RISCV_GOT_HI20)) {
					s32 hi20, lo12;
					Elf_Sym *hi20_sym =
						(Elf_Sym *)sechdrs[symindex].sh_addr
						+ ELF_RISCV_R_SYM(rel[j].r_info);
					unsigned long hi20_sym_val =
						hi20_sym->st_value
						+ rel[j].r_addend;

					/* Calculate lo12 */
					size_t offset = hi20_sym_val - hi20_loc;
					if (IS_ENABLED(CONFIG_MODULE_SECTIONS)
					    && hi20_type == R_RISCV_GOT_HI20) {
						offset = module_emit_got_entry(
							 me, hi20_sym_val);
						offset = offset - hi20_loc;
					}
					hi20 = (offset + 0x800) & 0xfffff000;
					lo12 = offset - hi20;
					v = lo12;

					break;
				}
			}
			if (j == sechdrs[relsec].sh_size / sizeof(*rel)) {
				pr_err(
				  "%s: Can not find HI20 relocation information\n",
				  me->name);
				return -EINVAL;
			}
		}

		res = handler(me, location, v);
		if (res)
			return res;
	}

	return 0;
}

#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
void *module_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, MODULES_VADDR,
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}
#endif

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s;

	s = find_section(hdr, sechdrs, ".alternative");
	if (s)
		apply_module_alternatives((void *)s->sh_addr, s->sh_size);

	return 0;
}
