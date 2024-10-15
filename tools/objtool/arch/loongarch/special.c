// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

#include <objtool/special.h>

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct reloc *reloc)
{
	return false;
}

static struct reloc *find_reloc_by_table_annotate(struct objtool_file *file,
						  struct instruction *insn)
{
	struct section *rsec;
	struct reloc *reloc;
	unsigned long offset;

	rsec = find_section_by_name(file->elf, ".rela.discard.tablejump_annotate");
	if (!rsec)
		return NULL;

	for_each_reloc(rsec, reloc) {
		if (reloc->sym->sec->rodata)
			continue;

		if (strcmp(insn->sec->name, reloc->sym->sec->name))
			continue;

		offset = reloc->sym->offset;
		if (insn->offset == offset) {
			reloc++;
			return reloc;
		}
	}

	return NULL;
}

struct reloc *arch_find_switch_table(struct objtool_file *file,
				     struct instruction *insn)
{
	struct reloc *annotate_reloc;
	struct reloc *rodata_reloc;
	struct section *table_sec;
	unsigned long table_offset;

	annotate_reloc = find_reloc_by_table_annotate(file, insn);
	if (!annotate_reloc) {
		annotate_reloc = find_reloc_by_dest_range(file->elf, insn->sec,
							  insn->offset, insn->len);
		if (!annotate_reloc)
			return NULL;

		if (!annotate_reloc->sym->sec->rodata)
			return NULL;

		if (reloc_type(annotate_reloc) != R_LARCH_NONE)
			return NULL;
	}

	table_sec = annotate_reloc->sym->sec;
	table_offset = annotate_reloc->sym->offset;

	/*
	 * Each table entry has a rela associated with it.  The rela
	 * should reference text in the same function as the original
	 * instruction.
	 */
	rodata_reloc = find_reloc_by_dest(file->elf, table_sec, table_offset);
	if (!rodata_reloc)
		return NULL;

	return rodata_reloc;
}
