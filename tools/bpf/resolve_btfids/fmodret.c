// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read the records which the bpf_scan_ir compiler plugin writes to
 * .BTF_fmodret_candidates, see scripts/llvm-plugins/bpf_scan_ir.cpp, and find
 * the functions which can become fmod_ret targets. A record lists the errors
 * which clean paths of a function return, that is paths without side effects.
 *
 * A function is chosen if
 *  - exactly one record describes its body, or one record of a strong
 *    definition next to records of the weak ones it overrides,
 *  - the record is of a strong definition or the symbol is still weak,
 *  - the record lists at least one error,
 *  - it has an ftrace call site and is not init, exit or noinstr code,
 *  - its name belongs to exactly one ELF function and one BTF FUNC,
 *  - it returns an integer of the size the record describes.
 *
 * The plugin records no errors for functions which return pointers yet.
 */

#include <errno.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <linux/kernel.h>

#include "fmodret.h"
#include "../../../scripts/bpf/fmodret_metadata.h"

#define FMODRET_CANDIDATES_SECTION ".BTF_fmodret_candidates"
#define NO_FUNCTION SIZE_MAX

struct elf_function {
	const char *name;
	GElf_Addr value;
	GElf_Xword size;
	Elf64_Section shndx;
	bool traceable;
	/* The symbol is weak: no strong definition replaced it at the link */
	bool weak_symbol;
	/* The records which describe the body at this address */
	unsigned int nr_strong, nr_weak;
	size_t strong, weak;
};

struct elf_function_list {
	struct elf_function *functions;
	size_t nr;
	size_t capacity;
};

struct fmodret_stats {
	size_t records, unmapped, with_values;
	size_t ambiguous_body, not_traceable, ambiguous_name;
	size_t overridden, no_btf, return_mismatch, added;
};

static int find_section(Elf *elf, size_t shstrndx, const char *wanted,
			Elf_Scn **result)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		const char *name;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name)
			return -1;
		if (!strcmp(name, wanted)) {
			*result = scn;
			return 0;
		}
	}

	*result = NULL;
	return 0;
}

static int find_symbol(Elf *elf, const char *wanted, GElf_Sym *result,
		       bool *found)
{
	Elf_Scn *scn = NULL;

	*found = false;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_symbols;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (shdr.sh_type != SHT_SYMTAB)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;
		nr_symbols = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_symbols; i++) {
			const char *name;
			GElf_Sym sym;

			if (!gelf_getsym(data, i, &sym))
				return -1;
			if (sym.st_shndx == SHN_UNDEF || !sym.st_name)
				continue;
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!name)
				return -1;
			if (strcmp(name, wanted))
				continue;
			*result = sym;
			*found = true;
			return 0;
		}
	}
	return 0;
}

static int section_for_address(Elf *elf, GElf_Addr address,
			       Elf64_Section *result)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (!(shdr.sh_flags & SHF_EXECINSTR) || address < shdr.sh_addr ||
		    address - shdr.sh_addr >= shdr.sh_size)
			continue;
		*result = elf_ndxscn(scn);
		return 0;
	}
	*result = SHN_UNDEF;
	return 0;
}

static bool relocation_offset(const GElf_Shdr *target, GElf_Addr offset,
			      size_t width, size_t *result)
{
	if (target->sh_size < width)
		return false;
	if (offset >= target->sh_addr &&
	    offset - target->sh_addr <= target->sh_size - width) {
		*result = offset - target->sh_addr;
		return true;
	}
	/* ET_REL relocation offsets are relative to their target section. */
	if (offset <= target->sh_size - width) {
		*result = offset;
		return true;
	}
	return false;
}

static uint64_t read_elf_value(const unsigned char *p, size_t size,
			       unsigned int encoding)
{
	uint64_t value = 0;
	size_t i;

	if (encoding == ELFDATA2LSB) {
		for (i = 0; i < size; i++)
			value |= (uint64_t)p[i] << (8 * i);
	} else {
		for (i = 0; i < size; i++)
			value = (value << 8) | p[i];
	}
	return value;
}

static int copy_section_data(Elf_Scn *scn, const GElf_Shdr *shdr,
			     unsigned char **result)
{
	Elf_Data *data = NULL;
	unsigned char *buf;

	buf = calloc(1, shdr->sh_size ?: 1);
	if (!buf)
		return -ENOMEM;
	while ((data = elf_getdata(scn, data))) {
		if (data->d_off > shdr->sh_size ||
		    data->d_size > shdr->sh_size - data->d_off) {
			free(buf);
			return -EINVAL;
		}
		memcpy(buf + data->d_off, data->d_buf, data->d_size);
	}
	*result = buf;
	return 0;
}

static int add_elf_function(struct elf_function_list *list, const char *name,
			    const GElf_Sym *sym)
{
	struct elf_function *functions;
	size_t capacity;

	if (list->nr == list->capacity) {
		capacity = list->capacity ? 2 * list->capacity : 1024;
		if (capacity > SIZE_MAX / sizeof(*functions))
			return -E2BIG;
		functions = realloc(list->functions, capacity * sizeof(*functions));
		if (!functions)
			return -ENOMEM;
		list->functions = functions;
		list->capacity = capacity;
	}

	list->functions[list->nr++] = (struct elf_function) {
		.name = name,
		.value = sym->st_value,
		.size = sym->st_size,
		.shndx = sym->st_shndx,
		.weak_symbol = GELF_ST_BIND(sym->st_info) == STB_WEAK,
		.strong = NO_FUNCTION,
		.weak = NO_FUNCTION,
	};
	return 0;
}

static int collect_elf_functions(Elf *elf, struct elf_function_list *list)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_symbols;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (shdr.sh_type != SHT_SYMTAB)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;

		nr_symbols = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_symbols; i++) {
			const char *name;
			GElf_Sym sym;
			int err;

			if (!gelf_getsym(data, i, &sym))
				return -1;
			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC ||
			    sym.st_shndx == SHN_UNDEF || !sym.st_name)
				continue;
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!name)
				return -1;
			err = add_elf_function(list, name, &sym);
			if (err)
				return err;
		}
	}
	return 0;
}

static int cmp_elf_function_location(const void *va, const void *vb)
{
	const struct elf_function *a = va;
	const struct elf_function *b = vb;

	if (a->shndx != b->shndx)
		return a->shndx > b->shndx ? 1 : -1;
	if (a->value != b->value)
		return a->value > b->value ? 1 : -1;
	return 0;
}

static int cmp_elf_function_name(const void *va, const void *vb)
{
	const struct elf_function *a = va;
	const struct elf_function *b = vb;

	return strcmp(a->name, b->name) ?: cmp_elf_function_location(va, vb);
}

/* Return the first function at VALUE in SHNDX. Functions are sorted by location. */
static size_t function_at(const struct elf_function_list *list,
			  Elf64_Section shndx, GElf_Addr value)
{
	size_t lo = 0, hi = list->nr;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const struct elf_function *f = &list->functions[mid];

		if (f->shndx < shndx || (f->shndx == shndx && f->value < value))
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == list->nr || list->functions[lo].shndx != shndx ||
	    list->functions[lo].value != value)
		return NO_FUNCTION;
	return lo;
}

static bool function_contains(const struct elf_function *function,
			      GElf_Addr address)
{
	if (address < function->value)
		return false;
	if (!function->size)
		return address == function->value;
	return address - function->value < function->size;
}

enum ftrace_site_kind {
	FTRACE_SITE_MCOUNT,
	FTRACE_SITE_PATCHABLE,
	FTRACE_SITE_UNKNOWN,
};

/*
 * The NOPs which arm64 puts before a function with CALL_OPS. From the entry of
 * an overridden weak function, whose body has no symbol left, a longer distance
 * could reach the next function. Other arches may need more.
 */
#define MAX_PATCHABLE_FUNCTION_ENTRY_SIZE 8

/* Return true if function I or another function at its address contains ADDRESS */
static bool alias_contains(const struct elf_function_list *list, size_t i,
			   GElf_Addr address)
{
	const struct elf_function *f = &list->functions[i];

	for (;;) {
		if (function_contains(&list->functions[i], address))
			return true;
		if (!i || list->functions[i - 1].shndx != f->shndx ||
		    list->functions[i - 1].value != f->value)
			return false;
		i--;
	}
}

/*
 * Mark the functions at (SHNDX, VALUE) traceable, or, with CHECK, only those
 * which contain ADDRESS.
 */
static void mark_aliases(struct elf_function_list *list, Elf64_Section shndx,
			 GElf_Addr value, GElf_Addr address, bool check)
{
	size_t first = function_at(list, shndx, value), i;

	if (first == NO_FUNCTION)
		return;
	for (i = first; i < list->nr && list->functions[i].shndx == shndx &&
	     list->functions[i].value == value; i++) {
		if (check && !function_contains(&list->functions[i], address))
			continue;
		list->functions[i].traceable = true;
	}
}

/*
 * Mark the function containing an ftrace call site. Functions are sorted by
 * section and address. Mark all aliases at the same address: at run time BTF
 * attachment is name based and may resolve to any of them.
 */
static void mark_traceable_function(struct elf_function_list *list,
				    Elf64_Section shndx, GElf_Addr address,
				    enum ftrace_site_kind kind)
{
	size_t left = 0;
	size_t right = list->nr;
	size_t first;

	/* Find the first function after ADDRESS in SHNDX. */
	while (left < right) {
		size_t middle = left + (right - left) / 2;
		struct elf_function *function = &list->functions[middle];

		if (function->shndx < shndx ||
		    (function->shndx == shndx && function->value <= address))
			left = middle + 1;
		else
			right = middle;
	}
	/*
	 * A patchable entry is at the start of its function, a few bytes into it
	 * (after an arm64 BTI) or in the NOPs before it
	 */
	first = SIZE_MAX;
	if (kind != FTRACE_SITE_MCOUNT) {
		if (left && list->functions[left - 1].shndx == shndx &&
		    address - list->functions[left - 1].value <
					MAX_PATCHABLE_FUNCTION_ENTRY_SIZE &&
		    alias_contains(list, left - 1, address))
			first = left - 1;
		else if (left < list->nr && list->functions[left].shndx == shndx &&
			 list->functions[left].value - address <=
					MAX_PATCHABLE_FUNCTION_ENTRY_SIZE)
			first = left;
	}
	if (first != SIZE_MAX) {
		mark_aliases(list, shndx, list->functions[first].value, address, false);
		return;
	}
	if (kind == FTRACE_SITE_PATCHABLE || !left)
		return;

	/* The nearest preceding function owns the call site. */
	first = left - 1;
	if (list->functions[first].shndx != shndx)
		return;
	mark_aliases(list, shndx, list->functions[first].value, address, true);
}

static int mark_relocated_ftrace_sites(Elf *elf, size_t target_ndx,
				       const unsigned char *target_data,
				       const GElf_Shdr *target_shdr,
				       size_t begin, size_t end,
				       size_t ptr_size, unsigned int encoding,
				       struct elf_function_list *functions,
				       enum ftrace_site_kind kind,
				       bool *relocated)
{
	Elf_Scn *scn = NULL;

	*relocated = false;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_relocations;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if ((shdr.sh_type != SHT_RELA && shdr.sh_type != SHT_REL) ||
		    (shdr.sh_info && shdr.sh_info != target_ndx))
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;

		nr_relocations = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_relocations; i++) {
			Elf_Scn *symtab_scn;
			Elf_Data *symtab_data;
			GElf_Shdr symtab_shdr;
			GElf_Sxword addend;
			GElf_Addr raw_offset;
			GElf_Addr address;
			GElf_Sym sym;
			size_t sym_ndx;
			size_t offset;

			if (shdr.sh_type == SHT_RELA) {
				GElf_Rela rela;

				if (!gelf_getrela(data, i, &rela))
					return -1;
				sym_ndx = GELF_R_SYM(rela.r_info);
				raw_offset = rela.r_offset;
				addend = rela.r_addend;
			} else {
				GElf_Rel rel;

				if (!gelf_getrel(data, i, &rel))
					return -1;
				sym_ndx = GELF_R_SYM(rel.r_info);
				raw_offset = rel.r_offset;
				if (!relocation_offset(target_shdr, raw_offset,
						       ptr_size, &offset))
					continue;
				addend = read_elf_value(target_data + offset,
							ptr_size, encoding);
			}
			if (!relocation_offset(target_shdr, raw_offset, ptr_size,
					       &offset))
				continue;
			if (offset < begin || offset >= end)
				continue;
			*relocated = true;

			/*
			 * PIE vmlinux uses symbol-less RELATIVE relocations. Its
			 * addend is the link-time call-site address, represented as
			 * a signed ELF addend.
			 */
			if (!sym_ndx) {
				Elf64_Section target_shndx;

				address = (GElf_Addr)addend;
				if (section_for_address(elf, address,
							&target_shndx))
					return -1;
				if (target_shndx != SHN_UNDEF)
					mark_traceable_function(functions,
								target_shndx,
								address, kind);
				continue;
			}

			symtab_scn = elf_getscn(elf, shdr.sh_link);
			if (!symtab_scn ||
			    !gelf_getshdr(symtab_scn, &symtab_shdr))
				return -1;
			symtab_data = elf_getdata(symtab_scn, NULL);
			if (!symtab_data || elf_getdata(symtab_scn, symtab_data) ||
			    !gelf_getsym(symtab_data, sym_ndx, &sym))
				return -1;
			if (sym.st_shndx == SHN_UNDEF)
				continue;
			if (sym.st_shndx >= SHN_LORESERVE)
				continue;
			if (addend < 0) {
				GElf_Addr delta = -(addend + 1);

				delta++;
				if (delta > sym.st_value)
					continue;
				address = sym.st_value - delta;
			} else {
				if ((GElf_Addr)addend > UINT64_MAX - sym.st_value)
					continue;
				address = sym.st_value + addend;
			}
			mark_traceable_function(functions, sym.st_shndx, address,
						kind);
		}
	}
	return 0;
}

static int read_ftrace_site_range(Elf *elf, Elf_Scn *scn, size_t begin,
				  size_t end, size_t ptr_size,
				  unsigned int encoding,
				  struct elf_function_list *functions,
				  enum ftrace_site_kind kind)
{
	unsigned char *buf = NULL;
	GElf_Shdr shdr;
	bool relocated;
	size_t offset;
	int err;

	if (!gelf_getshdr(scn, &shdr))
		return -1;
	if (begin > end || end > shdr.sh_size ||
	    (end - begin) % ptr_size)
		return -EINVAL;
	if (begin == end)
		return 0;
	err = copy_section_data(scn, &shdr, &buf);
	if (err)
		return err;
	err = mark_relocated_ftrace_sites(elf, elf_ndxscn(scn), buf, &shdr,
					  begin, end, ptr_size, encoding,
					  functions, kind, &relocated);
	if (err || relocated)
		goto out;

	for (offset = begin; offset < end; offset += ptr_size) {
		GElf_Addr address;
		Elf64_Section shndx;

		address = read_elf_value(buf + offset, ptr_size, encoding);
		err = section_for_address(elf, address, &shndx);
		if (err)
			goto out;
		if (shndx != SHN_UNDEF)
			mark_traceable_function(functions, shndx, address, kind);
	}
out:
	free(buf);
	return err;
}

static bool section_prefix(const char *name, const char *prefix)
{
	size_t len = strlen(prefix);

	return !strncmp(name, prefix, len) &&
	       (!name[len] || name[len] == '.');
}

static bool section_cannot_be_attached(const char *name)
{
	return section_prefix(name, ".init.text") ||
	       section_prefix(name, ".exit.text") ||
	       section_prefix(name, ".noinstr.text");
}

static int remove_unattachable_functions(Elf *elf,
					 struct elf_function_list *functions,
					 size_t shstrndx)
{
	GElf_Sym noinstr_start;
	GElf_Sym noinstr_end;
	bool found_start;
	bool found_end;
	size_t i;
	int err;

	err = find_symbol(elf, "__noinstr_text_start", &noinstr_start,
			  &found_start);
	if (err)
		return err;
	err = find_symbol(elf, "__noinstr_text_end", &noinstr_end, &found_end);
	if (err)
		return err;

	for (i = 0; i < functions->nr; i++) {
		struct elf_function *function = &functions->functions[i];
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		if (!function->traceable)
			continue;
		scn = elf_getscn(elf, function->shndx);
		if (!scn || !gelf_getshdr(scn, &shdr))
			return -1;
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name)
			return -1;
		if (section_cannot_be_attached(name))
			function->traceable = false;
		else if (found_start && found_end &&
			 function->shndx == noinstr_start.st_shndx &&
			 noinstr_start.st_shndx == noinstr_end.st_shndx &&
			 function->value >= noinstr_start.st_value &&
			 function->value < noinstr_end.st_value)
			function->traceable = false;
	}
	return 0;
}

static int read_ftrace_symbol_range(Elf *elf, const GElf_Sym *start,
				    const GElf_Sym *stop, size_t ptr_size,
				    unsigned int encoding,
				    struct elf_function_list *functions,
				    enum ftrace_site_kind kind)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t begin;
	size_t end;

	if (start->st_shndx != stop->st_shndx)
		return -EINVAL;
	scn = elf_getscn(elf, start->st_shndx);
	if (!scn || !gelf_getshdr(scn, &shdr))
		return -1;
	if (start->st_value < shdr.sh_addr || stop->st_value < start->st_value ||
	    stop->st_value - shdr.sh_addr > shdr.sh_size)
		return -EINVAL;
	begin = start->st_value - shdr.sh_addr;
	end = stop->st_value - shdr.sh_addr;
	return read_ftrace_site_range(elf, scn, begin, end, ptr_size, encoding,
				       functions, kind);
}

/*
 * Mark the functions with an ftrace call site. A module keeps the sites in the
 * section FTRACE_CALLSITE_SECTION: __patchable_function_entries if PATCHABLE,
 * else __mcount_loc. x86 also has call padding entries, which are not call
 * sites, in __patchable_function_entries. vmlinux merges the sites into init
 * data between the __start_mcount_loc and __stop_mcount_loc symbols, see
 * MCOUNT_REC().
 */
static int read_ftrace_sites(Elf *elf, size_t shstrndx,
			     size_t ptr_size, unsigned int encoding,
			     struct elf_function_list *functions, bool patchable)
{
	const char *section = patchable ? "__patchable_function_entries" : "__mcount_loc";
	Elf_Scn *scn = NULL;
	GElf_Sym start;
	GElf_Sym stop;
	GElf_Sym patchable_start;
	GElf_Sym patchable_stop;
	bool found_start;
	bool found_stop;
	bool found_patchable_start;
	bool found_patchable_stop;
	GElf_Shdr shdr;
	int err;

	err = find_section(elf, shstrndx, section, &scn);
	if (err)
		return err;
	if (scn) {
		if (!gelf_getshdr(scn, &shdr))
			return -1;
		err = read_ftrace_site_range(elf, scn, 0, shdr.sh_size,
					     ptr_size, encoding, functions,
					     patchable ? FTRACE_SITE_PATCHABLE :
							 FTRACE_SITE_MCOUNT);
		if (err)
			return err;
	}

	err = find_symbol(elf, "__start_mcount_loc", &start, &found_start);
	if (err)
		return err;
	err = find_symbol(elf, "__stop_mcount_loc", &stop, &found_stop);
	if (err)
		return err;
	err = find_symbol(elf, "__start_patchable_function_entries",
			  &patchable_start, &found_patchable_start);
	if (err)
		return err;
	err = find_symbol(elf, "__stop_patchable_function_entries",
			  &patchable_stop, &found_patchable_stop);
	if (err)
		return err;
	if (found_start && found_stop) {
		if (found_patchable_start && found_patchable_stop) {
			err = read_ftrace_symbol_range(elf, &start,
						       &patchable_start,
						       ptr_size, encoding,
						       functions,
						       FTRACE_SITE_MCOUNT);
			if (err)
				return err;
			err = read_ftrace_symbol_range(elf, &patchable_start,
						       &patchable_stop,
						       ptr_size, encoding,
						       functions,
						       FTRACE_SITE_PATCHABLE);
		} else {
			err = read_ftrace_symbol_range(elf, &start, &stop,
						       ptr_size, encoding,
						       functions,
						       FTRACE_SITE_UNKNOWN);
		}
		if (err)
			return err;
	}

	return remove_unattachable_functions(elf, functions, shstrndx);
}

/*
 * Find the function each record points to. In a module the pointer is a
 * relocation, in a linked image it is the address. REFS maps each pointer
 * sized slot of the section to a function.
 */
static int resolve_record_relocations(Elf *elf, const struct elf_function_list *functions,
				      size_t metadata_ndx, const GElf_Shdr *metadata_shdr,
				      const unsigned char *metadata, size_t *refs,
				      size_t ptr_size, unsigned int encoding)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		Elf_Data *data, *symbols;
		Elf_Scn *symtab;
		GElf_Shdr shdr;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if ((shdr.sh_type != SHT_RELA && shdr.sh_type != SHT_REL) ||
		    shdr.sh_info != metadata_ndx)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		symtab = elf_getscn(elf, shdr.sh_link);
		symbols = symtab ? elf_getdata(symtab, NULL) : NULL;
		if (!data || !symbols || elf_getdata(scn, data))
			return -1;
		for (i = 0; i < shdr.sh_size / shdr.sh_entsize; i++) {
			GElf_Rela rela;
			GElf_Sym sym;
			size_t offset;

			if (shdr.sh_type == SHT_RELA) {
				if (!gelf_getrela(data, i, &rela))
					return -1;
			} else {
				GElf_Rel rel;

				if (!gelf_getrel(data, i, &rel))
					return -1;
				rela = (GElf_Rela){ .r_offset = rel.r_offset,
						    .r_info = rel.r_info };
				/* REL addends are stored in the pointer itself. */
				if (!relocation_offset(metadata_shdr, rel.r_offset, ptr_size,
						       &offset))
					return -EINVAL;
				rela.r_addend = read_elf_value(metadata + offset, ptr_size,
							       encoding);
			}
			if (!relocation_offset(metadata_shdr, rela.r_offset, ptr_size, &offset) ||
			    offset % ptr_size)
				return -EINVAL;
			if (!gelf_getsym(symbols, GELF_R_SYM(rela.r_info), &sym))
				return -1;
			if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE)
				continue;
			refs[offset / ptr_size] = function_at(functions, sym.st_shndx,
							      sym.st_value + rela.r_addend);
		}
	}
	return 0;
}

static size_t record_function(Elf *elf, const struct elf_function_list *functions,
			      const unsigned char *buf, const size_t *refs,
			      size_t offset, size_t ptr_size, unsigned int encoding)
{
	Elf64_Section section;
	GElf_Ehdr ehdr;
	GElf_Addr value;

	if (refs[offset / ptr_size] != NO_FUNCTION)
		return refs[offset / ptr_size];
	if (!gelf_getehdr(elf, &ehdr) || ehdr.e_type == ET_REL)
		return NO_FUNCTION;
	value = read_elf_value(buf + offset, ptr_size, encoding);
	if (!value || section_for_address(elf, value, &section))
		return NO_FUNCTION;
	return function_at(functions, section, value);
}

/* Remember the records of a body for all the functions at its address */
static void add_record(struct elf_function_list *functions, size_t first,
		       size_t offset, bool weak)
{
	struct elf_function *f = &functions->functions[first];
	size_t i;

	for (i = first; i < functions->nr &&
	     !cmp_elf_function_location(f, &functions->functions[i]); i++) {
		if (weak) {
			functions->functions[i].nr_weak++;
			functions->functions[i].weak = offset;
		} else {
			functions->functions[i].nr_strong++;
			functions->functions[i].strong = offset;
		}
	}
}

static int parse_records(Elf *elf, struct elf_function_list *functions,
			 const unsigned char *buf, size_t size, const size_t *refs,
			 size_t ptr_size, unsigned int encoding,
			 struct fmodret_stats *stats)
{
	size_t offset = 0;

	while (offset < size) {
		unsigned int flags, length, nr_values;
		size_t function;

		if (size - offset < FMODRET_META_HEADER_SIZE(ptr_size) ||
		    read_elf_value(buf + offset, 4, encoding) != FMODRET_META_MAGIC ||
		    read_elf_value(buf + offset + 4, 4, encoding) != FMODRET_META_VERSION)
			goto invalid;
		length = read_elf_value(buf + offset + 8, 4, encoding);
		flags = read_elf_value(buf + offset + 12, 4, encoding);
		nr_values = read_elf_value(buf + offset + 16 + ptr_size, 4, encoding);
		if (length < FMODRET_META_HEADER_SIZE(ptr_size) || length > size - offset ||
		    length % ptr_size ||
		    nr_values != (length - FMODRET_META_HEADER_SIZE(ptr_size)) /
				 FMODRET_META_VALUE_SIZE ||
		    (length - FMODRET_META_HEADER_SIZE(ptr_size)) % FMODRET_META_VALUE_SIZE)
			goto invalid;
		stats->records++;
		function = record_function(elf, functions, buf, refs, offset + 16,
					   ptr_size, encoding);
		/* A function in a discarded section has no ELF function */
		if (function == NO_FUNCTION)
			stats->unmapped++;
		else
			add_record(functions, function, offset, flags & FMODRET_FN_WEAK);
		offset += length;
	}
	return 0;
invalid:
	fprintf(stderr,
		"invalid or old fmodret metadata at offset %#zx; rebuild all plugin objects\n",
		offset);
	return -EINVAL;
}

/* Return the record which describes the body of F, or NO_FUNCTION */
static size_t chosen_record(const struct elf_function *f)
{
	if (f->nr_strong == 1)
		return f->strong;
	if (!f->nr_strong && f->nr_weak == 1)
		return f->weak;
	return NO_FUNCTION;
}

struct btf_func {
	const char *name;
	__u32 id;
};

static int cmp_btf_func(const void *a, const void *b)
{
	const struct btf_func *x = a, *y = b;

	return strcmp(x->name, y->name);
}

/*
 * Return the FUNCs of BTF, without those of its base, sorted by name. The BTF
 * is sorted only after the tags are added, and searching all of it for each
 * candidate is slow for vmlinux.
 */
static struct btf_func *collect_btf_funcs(const struct btf *btf, size_t *cnt)
{
	const struct btf *base = btf__base_btf(btf);
	__u32 id, nr_types = btf__type_cnt(btf);
	struct btf_func *funcs;
	size_t n = 0;

	funcs = malloc(nr_types * sizeof(*funcs));
	if (!funcs)
		return NULL;
	for (id = base ? btf__type_cnt(base) : 1; id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!btf_is_func(t))
			continue;
		funcs[n].name = btf__name_by_offset(btf, t->name_off);
		funcs[n++].id = id;
	}
	qsort(funcs, n, sizeof(*funcs), cmp_btf_func);
	*cnt = n;
	return funcs;
}

/* Return the BTF ID of the only FUNC named NAME, or 0 */
static int find_btf_func(const struct btf_func *funcs, size_t cnt, const char *name)
{
	const struct btf_func key = { .name = name }, *f;

	f = bsearch(&key, funcs, cnt, sizeof(*funcs), cmp_btf_func);
	if (!f)
		return 0;
	if ((f > funcs && !strcmp(f[-1].name, name)) ||
	    (f + 1 < funcs + cnt && !strcmp(f[1].name, name)))
		return 0;
	return f->id;
}

/* Return the size of the integer which FUNC returns, or 0 */
static __u32 btf_func_int_return_size(const struct btf *btf, int func)
{
	const struct btf_type *t = btf__type_by_id(btf, func);
	int ret;

	t = btf__type_by_id(btf, t->type);
	if (!t || !btf_is_func_proto(t) || !t->type)
		return 0;
	ret = btf__resolve_type(btf, t->type);
	if (ret < 0)
		return 0;
	t = btf__type_by_id(btf, ret);
	if (!btf_is_int(t) && !btf_is_enum(t) && !btf_is_enum64(t))
		return 0;
	return t->size;
}

/* Format the values of the record at OFFSET as "-22,-12" */
static char *format_values(const unsigned char *buf, size_t offset, size_t ptr_size,
			   unsigned int encoding)
{
	unsigned int nr = read_elf_value(buf + offset + 16 + ptr_size, 4, encoding);
	const unsigned char *p = buf + offset + FMODRET_META_HEADER_SIZE(ptr_size);
	size_t size = (size_t)nr * 21 + 1, len = 0;
	char *s = malloc(size);
	unsigned int i;

	if (!s)
		return NULL;
	for (i = 0; i < nr; i++) {
		int64_t value = read_elf_value(p + i * FMODRET_META_VALUE_SIZE,
					       FMODRET_META_VALUE_SIZE, encoding);

		len += snprintf(s + len, size - len, "%s%lld", i ? "," : "",
				(long long)value);
	}
	s[len] = 0;
	return s;
}

static int cmp_retval(const void *va, const void *vb)
{
	const struct fmodret_retval *a = va;
	const struct fmodret_retval *b = vb;

	return a->btf_id > b->btf_id ? 1 : a->btf_id < b->btf_id ? -1 : 0;
}

/* Choose the targets among the functions and describe them in RESULT */
static int choose_functions(struct elf_function_list *functions, const struct btf *btf,
			    const struct btf_func *btf_funcs, size_t nr_btf_funcs,
			    const unsigned char *buf, size_t ptr_size,
			    unsigned int encoding, struct fmodret_retvals *result,
			    struct fmodret_stats *stats, int verbose)
{
	size_t i = 0, j;

	qsort(functions->functions, functions->nr, sizeof(*functions->functions),
	      cmp_elf_function_name);
	for (i = 0; i < functions->nr; i = j) {
		const struct elf_function *f = &functions->functions[i];
		size_t record = chosen_record(f);
		const char *reason = NULL;
		unsigned int flags = 0;
		struct fmodret_retval *r;
		__u32 size;
		int id = 0;

		for (j = i + 1; j < functions->nr; j++)
			if (strcmp(f->name, functions->functions[j].name))
				break;

		if (!f->nr_strong && !f->nr_weak)
			continue;
		if (record == NO_FUNCTION) {
			stats->ambiguous_body++;
			reason = "ambiguous-body";
			goto rejected;
		}
		/*
		 * A strong definition without values has no record. If it
		 * replaced a weak one, only the record of the weak one points
		 * to its body.
		 */
		if (!f->nr_strong && !f->weak_symbol) {
			stats->overridden++;
			reason = "overridden-weak";
			goto rejected;
		}
		if (!read_elf_value(buf + record + 16 + ptr_size, 4, encoding))
			continue;
		stats->with_values++;
		flags = read_elf_value(buf + record + 12, 4, encoding);
		if (j - i != 1) {
			stats->ambiguous_name++;
			reason = "ambiguous-name";
			goto rejected;
		}
		if (!f->traceable) {
			stats->not_traceable++;
			reason = "not-traceable";
			goto rejected;
		}
		id = find_btf_func(btf_funcs, nr_btf_funcs, f->name);
		if (id <= 0) {
			stats->no_btf++;
			reason = "no-unique-BTF-FUNC";
			goto rejected;
		}
		size = btf_func_int_return_size(btf, id);
		if (size != (flags & FMODRET_FN_RET64 ? 8 : 4)) {
			stats->return_mismatch++;
			reason = "BTF-return-type";
		}
rejected:
		if (reason) {
			if (verbose > 1)
				fprintf(stderr, "fmodret: rejected %s: %s\n", f->name, reason);
			continue;
		}

		if (result->cnt == result->cap) {
			size_t cap = result->cap ? 2 * result->cap : 256;

			r = realloc(result->retvals, cap * sizeof(*r));
			if (!r)
				return -ENOMEM;
			result->retvals = r;
			result->cap = cap;
		}
		r = &result->retvals[result->cnt];
		r->btf_id = id;
		r->values = format_values(buf, record, ptr_size, encoding);
		if (!r->values)
			return -ENOMEM;
		result->cnt++;
		stats->added++;
		if (verbose > 1)
			fprintf(stderr, "fmodret: %s: BTF ID %d, retval %s\n",
				f->name, id, r->values);
	}
	if (result->cnt)
		qsort(result->retvals, result->cnt, sizeof(*result->retvals), cmp_retval);
	return 0;
}

int fmodret_collect(Elf *elf, const struct btf *btf, struct fmodret_retvals *result,
		    bool patchable_ftrace, int verbose)
{
	struct elf_function_list functions = {};
	struct btf_func *btf_funcs = NULL;
	struct fmodret_stats stats = {};
	unsigned char *buf = NULL;
	size_t nr_btf_funcs;
	size_t *refs = NULL;
	size_t shstrndx, ptr_size, i;
	unsigned int encoding;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	int err;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return -EINVAL;
	err = find_section(elf, shstrndx, FMODRET_CANDIDATES_SECTION, &scn);
	if (err || !scn)
		return err;
	if (!gelf_getshdr(scn, &shdr))
		return -EINVAL;
	ptr_size = gelf_getclass(elf) == ELFCLASS64 ? 8 : 4;
	encoding = elf_getident(elf, NULL)[EI_DATA];
	if (shdr.sh_size % ptr_size)
		return -EINVAL;

	err = collect_elf_functions(elf, &functions);
	if (err)
		goto out;
	qsort(functions.functions, functions.nr, sizeof(*functions.functions),
	      cmp_elf_function_location);

	err = copy_section_data(scn, &shdr, &buf);
	if (err)
		goto out;
	refs = malloc((shdr.sh_size / ptr_size ?: 1) * sizeof(*refs));
	if (!refs) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < shdr.sh_size / ptr_size; i++)
		refs[i] = NO_FUNCTION;
	err = resolve_record_relocations(elf, &functions, elf_ndxscn(scn), &shdr, buf,
					 refs, ptr_size, encoding);
	if (err)
		goto out;
	err = parse_records(elf, &functions, buf, shdr.sh_size, refs, ptr_size,
			    encoding, &stats);
	if (err)
		goto out;
	err = read_ftrace_sites(elf, shstrndx, ptr_size, encoding, &functions,
				patchable_ftrace);
	if (err)
		goto out;
	btf_funcs = collect_btf_funcs(btf, &nr_btf_funcs);
	if (!btf_funcs) {
		err = -ENOMEM;
		goto out;
	}
	err = choose_functions(&functions, btf, btf_funcs, nr_btf_funcs, buf, ptr_size,
			       encoding, result, &stats, verbose);
	if (err)
		goto out;

	if (verbose)
		fprintf(stderr,
			"fmodret: %zu records (%zu without a function), %zu functions with values, %zu added; rejected: %zu ambiguous body, %zu ambiguous name, %zu not traceable, %zu overridden weak, %zu without unique BTF FUNC, %zu BTF return type\n",
			stats.records, stats.unmapped, stats.with_values, stats.added,
			stats.ambiguous_body,
			stats.ambiguous_name, stats.not_traceable, stats.overridden,
			stats.no_btf, stats.return_mismatch);
out:
	if (err == -1)
		fprintf(stderr, "failed to read %s: %s\n", FMODRET_CANDIDATES_SECTION,
			elf_errmsg(-1));
	free(btf_funcs);
	free(refs);
	free(buf);
	free(functions.functions);
	return err;
}

void fmodret_free(struct fmodret_retvals *retvals)
{
	size_t i;

	for (i = 0; i < retvals->cnt; i++)
		free(retvals->retvals[i].values);
	free(retvals->retvals);
	retvals->retvals = NULL;
	retvals->cnt = retvals->cap = 0;
}
