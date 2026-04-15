// SPDX-License-Identifier: GPL-2.0-only
/*
 * gen_lineinfo.c - Generate address-to-source-line lookup tables from DWARF
 *
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Reads DWARF .debug_line from a vmlinux ELF file and outputs an assembly
 * file containing sorted lookup tables that the kernel uses to annotate
 * stack traces with source file:line information.
 *
 * Requires libdw from elfutils.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <elf.h>
#include <gelf.h>
#include <limits.h>

#include "../include/linux/mod_lineinfo.h"

static int module_mode;

static unsigned int skipped_overflow;

/* .text range for module mode (keep only runtime code) */
static unsigned long long text_section_start;
static unsigned long long text_section_end;

struct line_entry {
	unsigned int offset;	/* offset from _text */
	unsigned int file_id;
	unsigned int line;
};

struct file_entry {
	char *name;
	unsigned int id;
	unsigned int str_offset;
};

static struct line_entry *entries;
static unsigned int num_entries;
static unsigned int entries_capacity;

static struct file_entry *files;
static unsigned int num_files;
static unsigned int files_capacity;

#define FILE_HASH_BITS 13
#define FILE_HASH_SIZE (1 << FILE_HASH_BITS)

struct file_hash_entry {
	const char *name;
	unsigned int id;
};

static struct file_hash_entry file_hash[FILE_HASH_SIZE];

static unsigned int hash_str(const char *s)
{
	unsigned int h = 5381;

	for (; *s; s++)
		h = h * 33 + (unsigned char)*s;
	return h & (FILE_HASH_SIZE - 1);
}

static void add_entry(unsigned int offset, unsigned int file_id,
		      unsigned int line)
{
	if (num_entries >= entries_capacity) {
		entries_capacity = entries_capacity ? entries_capacity * 2 : 65536;
		entries = realloc(entries, entries_capacity * sizeof(*entries));
		if (!entries) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
	}
	entries[num_entries].offset = offset;
	entries[num_entries].file_id = file_id;
	entries[num_entries].line = line;
	num_entries++;
}

static unsigned int find_or_add_file(const char *name)
{
	unsigned int h = hash_str(name);

	/* Open-addressing lookup with linear probing */
	while (file_hash[h].name) {
		if (!strcmp(file_hash[h].name, name))
			return file_hash[h].id;
		h = (h + 1) & (FILE_HASH_SIZE - 1);
	}

	if (num_files >= 65535) {
		fprintf(stderr,
			"gen_lineinfo: too many source files (%u > 65535)\n",
			num_files);
		exit(1);
	}

	if (num_files >= files_capacity) {
		files_capacity = files_capacity ? files_capacity * 2 : 4096;
		files = realloc(files, files_capacity * sizeof(*files));
		if (!files) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
	}
	files[num_files].name = strdup(name);
	files[num_files].id = num_files;

	/* Insert into hash table (points to files[] entry) */
	file_hash[h].name = files[num_files].name;
	file_hash[h].id = num_files;

	num_files++;
	return num_files - 1;
}

/*
 * Well-known top-level directories in the kernel source tree.
 * Used as a fallback to recover relative paths from absolute DWARF paths
 * when comp_dir doesn't match (e.g. O= out-of-tree builds where comp_dir
 * is the build directory but source paths point into the source tree).
 */
static const char * const kernel_dirs[] = {
	"arch/", "block/", "certs/", "crypto/", "drivers/", "fs/",
	"include/", "init/", "io_uring/", "ipc/", "kernel/", "lib/",
	"mm/", "net/", "rust/", "samples/", "scripts/", "security/",
	"sound/", "tools/", "usr/", "virt/",
};

/*
 * Strip a filename to a kernel-relative path.
 *
 * For absolute paths, strip the comp_dir prefix (from DWARF) to get
 * a kernel-tree-relative path.  When that fails (e.g. O= builds where
 * comp_dir is the build directory), scan for a well-known kernel
 * top-level directory name in the path to recover the relative path.
 * Fall back to the basename as a last resort.
 *
 * For relative paths (common in modules), libdw may produce a bogus
 * doubled path like "net/foo/bar.c/net/foo/bar.c" due to ET_REL DWARF
 * quirks.  Detect and strip such duplicates.
 */
static const char *make_relative(const char *path, const char *comp_dir)
{
	const char *p;

	if (path[0] == '/') {
		/* Try comp_dir prefix from DWARF */
		if (comp_dir) {
			size_t len = strlen(comp_dir);

			if (!strncmp(path, comp_dir, len) && path[len] == '/') {
				const char *rel = path + len + 1;

				/*
				 * If comp_dir pointed to a subdirectory
				 * (e.g. arch/parisc/kernel) rather than
				 * the tree root, stripping it leaves a
				 * bare filename.  Fall through to the
				 * kernel_dirs scan so we recover the full
				 * relative path instead.
				 */
				if (strchr(rel, '/'))
					return rel;
			}
		}

		/*
		 * comp_dir prefix didn't help — either it didn't match
		 * or it was too specific and left a bare filename.
		 * Scan for a known kernel top-level directory component
		 * to find where the relative path starts.  This handles
		 * O= builds and arches where comp_dir is a subdirectory.
		 */
		for (p = path + 1; *p; p++) {
			if (*(p - 1) == '/') {
				for (unsigned int i = 0; i < sizeof(kernel_dirs) /
				     sizeof(kernel_dirs[0]); i++) {
					if (!strncmp(p, kernel_dirs[i],
						     strlen(kernel_dirs[i])))
						return p;
				}
			}
		}

		/* Fall back to basename */
		p = strrchr(path, '/');
		return p ? p + 1 : path;
	}

	/*
	 * Relative path — check for duplicated-path quirk from libdw
	 * on ET_REL files (e.g., "a/b.c/a/b.c" → "a/b.c").
	 */
	{
		size_t len = strlen(path);
		size_t mid = len / 2;

		if (len > 1 && path[mid] == '/' &&
		    !memcmp(path, path + mid + 1, mid))
			return path + mid + 1;
	}

	/*
	 * Bare filename with no directory component — try to recover the
	 * relative path using comp_dir.  Some toolchains/elfutils combos
	 * produce bare filenames where comp_dir holds the source directory.
	 * Construct the absolute path and run the kernel_dirs scan.
	 */
	if (!strchr(path, '/') && comp_dir && comp_dir[0] == '/') {
		static char buf[PATH_MAX];

		snprintf(buf, sizeof(buf), "%s/%s", comp_dir, path);
		for (p = buf + 1; *p; p++) {
			if (*(p - 1) == '/') {
				for (unsigned int i = 0; i < sizeof(kernel_dirs) /
				     sizeof(kernel_dirs[0]); i++) {
					if (!strncmp(p, kernel_dirs[i],
						     strlen(kernel_dirs[i])))
						return p;
				}
			}
		}
	}

	return path;
}

static int compare_entries(const void *a, const void *b)
{
	const struct line_entry *ea = a;
	const struct line_entry *eb = b;

	if (ea->offset != eb->offset)
		return ea->offset < eb->offset ? -1 : 1;
	if (ea->file_id != eb->file_id)
		return ea->file_id < eb->file_id ? -1 : 1;
	if (ea->line != eb->line)
		return ea->line < eb->line ? -1 : 1;
	return 0;
}

static unsigned long long find_text_addr(Elf *elf)
{
	size_t nsyms, i;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data;

		if (!gelf_getshdr(scn, &shdr))
			continue;
		if (shdr.sh_type != SHT_SYMTAB)
			continue;

		data = elf_getdata(scn, NULL);
		if (!data)
			continue;

		nsyms = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nsyms; i++) {
			GElf_Sym sym;
			const char *name;

			if (!gelf_getsym(data, i, &sym))
				continue;
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (name && !strcmp(name, "_text"))
				return sym.st_value;
		}
	}

	fprintf(stderr, "Cannot find _text symbol\n");
	exit(1);
}

static void find_text_section_range(Elf *elf)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		const char *name;

		if (!gelf_getshdr(scn, &shdr))
			continue;
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name && !strcmp(name, ".text")) {
			text_section_start = shdr.sh_addr;
			text_section_end = shdr.sh_addr + shdr.sh_size;
			return;
		}
	}
}

/*
 * Apply .rela.debug_line relocations to a mutable copy of .debug_line data.
 *
 * elfutils libdw (through at least 0.194) does NOT apply relocations for
 * ET_REL files when using dwarf_begin_elf().  The internal libdwfl layer
 * does this via __libdwfl_relocate(), but that API is not public.
 *
 * For DWARF5, the .debug_line file name table uses DW_FORM_line_strp
 * references into .debug_line_str.  Without relocation, all these offsets
 * resolve to 0 (or garbage), causing dwarf_linesrc()/dwarf_filesrc() to
 * return wrong filenames (typically the comp_dir for every file).
 *
 * This function applies the relocations manually so that the patched
 * .debug_line data can be fed to dwarf_begin_elf() and produce correct
 * results.
 *
 * See elfutils bug https://sourceware.org/bugzilla/show_bug.cgi?id=31447
 * A fix (dwelf_elf_apply_relocs) was proposed but not yet merged as of
 * elfutils 0.194: https://sourceware.org/pipermail/elfutils-devel/2024q3/007388.html
 */
/*
 * Determine the relocation type for a 32-bit absolute reference
 * on the given architecture.  Returns 0 if unknown.
 */
static unsigned int r_type_abs32(unsigned int e_machine)
{
	switch (e_machine) {
	case EM_X86_64:		return R_X86_64_32;
	case EM_386:		return R_386_32;
	case EM_AARCH64:	return R_AARCH64_ABS32;
	case EM_ARM:		return R_ARM_ABS32;
	case EM_RISCV:		return R_RISCV_32;
	case EM_S390:		return R_390_32;
	case EM_MIPS:		return R_MIPS_32;
	case EM_PPC64:		return R_PPC64_ADDR32;
	case EM_PPC:		return R_PPC_ADDR32;
	case EM_LOONGARCH:	return R_LARCH_32;
	case EM_PARISC:		return R_PARISC_DIR32;
	default:		return 0;
	}
}

static void apply_debug_line_relocations(Elf *elf)
{
	Elf_Scn *scn = NULL;
	Elf_Scn *debug_line_scn = NULL;
	Elf_Scn *rela_debug_line_scn = NULL;
	Elf_Scn *symtab_scn = NULL;
	GElf_Shdr shdr;
	GElf_Ehdr ehdr;
	unsigned int abs32_type;
	size_t shstrndx;
	Elf_Data *dl_data, *rela_data, *sym_data;
	GElf_Shdr rela_shdr, sym_shdr;
	size_t nrels, i;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		return;

	abs32_type = r_type_abs32(ehdr.e_machine);
	if (!abs32_type)
		return;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return;

	/* Find the relevant sections */
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		const char *name;

		if (!gelf_getshdr(scn, &shdr))
			continue;
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name)
			continue;

		if (!strcmp(name, ".debug_line"))
			debug_line_scn = scn;
		else if (!strcmp(name, ".rela.debug_line"))
			rela_debug_line_scn = scn;
		else if (shdr.sh_type == SHT_SYMTAB)
			symtab_scn = scn;
	}

	if (!debug_line_scn || !rela_debug_line_scn || !symtab_scn)
		return;

	dl_data = elf_getdata(debug_line_scn, NULL);
	rela_data = elf_getdata(rela_debug_line_scn, NULL);
	sym_data = elf_getdata(symtab_scn, NULL);
	if (!dl_data || !rela_data || !sym_data)
		return;

	if (!gelf_getshdr(rela_debug_line_scn, &rela_shdr))
		return;
	if (!gelf_getshdr(symtab_scn, &sym_shdr))
		return;

	nrels = rela_shdr.sh_size / rela_shdr.sh_entsize;

	for (i = 0; i < nrels; i++) {
		GElf_Rela rela;
		GElf_Sym sym;
		unsigned int r_type;
		size_t r_sym;
		uint32_t value;

		if (!gelf_getrela(rela_data, i, &rela))
			continue;

		r_type = GELF_R_TYPE(rela.r_info);
		r_sym = GELF_R_SYM(rela.r_info);

		/* Only handle the 32-bit absolute reloc for this arch */
		if (r_type != abs32_type)
			continue;

		if (!gelf_getsym(sym_data, r_sym, &sym))
			continue;

		/* Relocated value = sym.st_value + addend */
		value = (uint32_t)(sym.st_value + rela.r_addend);

		/* Patch the .debug_line data at the relocation offset */
		if (rela.r_offset + 4 <= dl_data->d_size)
			memcpy((char *)dl_data->d_buf + rela.r_offset,
			       &value, sizeof(value));
	}
}

static void process_dwarf(Dwarf *dwarf, unsigned long long text_addr)
{
	Dwarf_Off off = 0, next_off;
	size_t hdr_size;

	while (dwarf_nextcu(dwarf, off, &next_off, &hdr_size,
			    NULL, NULL, NULL) == 0) {
		Dwarf_Die cudie;
		Dwarf_Lines *lines;
		size_t nlines;
		Dwarf_Attribute attr;
		const char *comp_dir = NULL;

		if (!dwarf_offdie(dwarf, off + hdr_size, &cudie))
			goto next;

		if (dwarf_attr(&cudie, DW_AT_comp_dir, &attr))
			comp_dir = dwarf_formstring(&attr);

		if (dwarf_getsrclines(&cudie, &lines, &nlines) != 0)
			goto next;

		for (size_t i = 0; i < nlines; i++) {
			Dwarf_Line *line = dwarf_onesrcline(lines, i);
			Dwarf_Addr addr;
			const char *src;
			const char *rel;
			unsigned int file_id, loffset;
			int lineno;

			if (!line)
				continue;

			if (dwarf_lineaddr(line, &addr) != 0)
				continue;
			if (dwarf_lineno(line, &lineno) != 0)
				continue;
			if (lineno == 0)
				continue;

			src = dwarf_linesrc(line, NULL, NULL);
			if (!src)
				continue;

			if (addr < text_addr)
				continue;

			/*
			 * In module mode, keep only .text addresses.
			 * In ET_REL .ko files, .text, .init.text and
			 * .exit.text all have sh_addr == 0 and therefore
			 * overlapping address ranges.  Explicitly check
			 * against the .text bounds.
			 */
			if (module_mode && text_section_end > text_section_start &&
			    (addr < text_section_start || addr >= text_section_end))
				continue;

			{
				unsigned long long raw_offset = addr - text_addr;

				if (raw_offset > UINT_MAX) {
					skipped_overflow++;
					continue;
				}
				loffset = (unsigned int)raw_offset;
			}

			rel = make_relative(src, comp_dir);
			file_id = find_or_add_file(rel);

			add_entry(loffset, file_id, (unsigned int)lineno);
		}
next:
		off = next_off;
	}
}

static void deduplicate(void)
{
	unsigned int i, j;

	if (num_entries < 2)
		return;

	/* Sort by offset, then file_id, then line for stability */
	qsort(entries, num_entries, sizeof(*entries), compare_entries);

	/*
	 * Remove duplicate entries:
	 * - Same offset: keep first (deterministic from stable sort keys)
	 * - Same file:line as previous kept entry: redundant for binary
	 *   search -- any address between them resolves to the earlier one
	 */
	j = 0;
	for (i = 1; i < num_entries; i++) {
		if (entries[i].offset == entries[j].offset)
			continue;
		if (entries[i].file_id == entries[j].file_id &&
		    entries[i].line == entries[j].line)
			continue;
		j++;
		if (j != i)
			entries[j] = entries[i];
	}
	num_entries = j + 1;
}

/*
 * Emit the LEB128 delta-compressed data stream for one block.
 * Uses .uleb128/.sleb128 assembler directives for encoding.
 */
static void emit_block_data(unsigned int block)
{
	unsigned int base = block * LINEINFO_BLOCK_ENTRIES;
	unsigned int count = num_entries - base;

	if (count > LINEINFO_BLOCK_ENTRIES)
		count = LINEINFO_BLOCK_ENTRIES;

	/* Entry 0: file_id, line (both unsigned) */
	printf("\t.uleb128 %u\n", entries[base].file_id);
	printf("\t.uleb128 %u\n", entries[base].line);

	/* Entries 1..N: addr_delta (unsigned), file/line deltas (signed) */
	for (unsigned int i = 1; i < count; i++) {
		unsigned int idx = base + i;

		printf("\t.uleb128 %u\n",
		       entries[idx].offset - entries[idx - 1].offset);
		printf("\t.sleb128 %d\n",
		       (int)entries[idx].file_id - (int)entries[idx - 1].file_id);
		printf("\t.sleb128 %d\n",
		       (int)entries[idx].line - (int)entries[idx - 1].line);
	}
}

static void compute_file_offsets(void)
{
	unsigned int offset = 0;

	for (unsigned int i = 0; i < num_files; i++) {
		files[i].str_offset = offset;
		offset += strlen(files[i].name) + 1;
	}
}

static void print_escaped_asciz(const char *s)
{
	printf("\t.asciz \"");
	for (; *s; s++) {
		if (*s == '"' || *s == '\\')
			putchar('\\');
		putchar(*s);
	}
	printf("\"\n");
}

static void output_assembly(void)
{
	unsigned int num_blocks;

	num_blocks = num_entries ?
		(num_entries + LINEINFO_BLOCK_ENTRIES - 1) / LINEINFO_BLOCK_ENTRIES : 0;

	printf("/* SPDX-License-Identifier: GPL-2.0 */\n");
	printf("/*\n");
	printf(" * Automatically generated by scripts/gen_lineinfo\n");
	printf(" * Do not edit.\n");
	printf(" */\n\n");

	printf("\t.section .rodata, \"a\"\n\n");

	/* Number of entries */
	printf("\t.globl lineinfo_num_entries\n");
	printf("\t.balign 4\n");
	printf("lineinfo_num_entries:\n");
	printf("\t.long %u\n\n", num_entries);

	/* Number of files */
	printf("\t.globl lineinfo_num_files\n");
	printf("\t.balign 4\n");
	printf("lineinfo_num_files:\n");
	printf("\t.long %u\n\n", num_files);

	/* Number of blocks */
	printf("\t.globl lineinfo_num_blocks\n");
	printf("\t.balign 4\n");
	printf("lineinfo_num_blocks:\n");
	printf("\t.long %u\n\n", num_blocks);

	/* Block first-addresses for binary search */
	printf("\t.globl lineinfo_block_addrs\n");
	printf("\t.balign 4\n");
	printf("lineinfo_block_addrs:\n");
	for (unsigned int i = 0; i < num_blocks; i++)
		printf("\t.long 0x%x\n", entries[i * LINEINFO_BLOCK_ENTRIES].offset);

	/* Block byte offsets into compressed stream */
	printf("\t.globl lineinfo_block_offsets\n");
	printf("\t.balign 4\n");
	printf("lineinfo_block_offsets:\n");
	for (unsigned int i = 0; i < num_blocks; i++)
		printf("\t.long .Lblock_%u - lineinfo_data\n", i);

	/* Compressed data size */
	printf("\t.globl lineinfo_data_size\n");
	printf("\t.balign 4\n");
	printf("lineinfo_data_size:\n");
	printf("\t.long .Ldata_end - lineinfo_data\n\n");

	/* Compressed data stream */
	printf("\t.globl lineinfo_data\n");
	printf("lineinfo_data:\n");
	for (unsigned int i = 0; i < num_blocks; i++) {
		printf(".Lblock_%u:\n", i);
		emit_block_data(i);
	}
	printf(".Ldata_end:\n\n");

	/* File string offset table */
	printf("\t.globl lineinfo_file_offsets\n");
	printf("\t.balign 4\n");
	printf("lineinfo_file_offsets:\n");
	for (unsigned int i = 0; i < num_files; i++)
		printf("\t.long %u\n", files[i].str_offset);

	/* Filenames size */
	printf("\t.globl lineinfo_filenames_size\n");
	printf("\t.balign 4\n");
	printf("lineinfo_filenames_size:\n");
	printf("\t.long .Lfilenames_end - lineinfo_filenames\n\n");

	/* Concatenated NUL-terminated filenames */
	printf("\t.globl lineinfo_filenames\n");
	printf("lineinfo_filenames:\n");
	for (unsigned int i = 0; i < num_files; i++)
		print_escaped_asciz(files[i].name);
	printf(".Lfilenames_end:\n");
}

static void output_module_assembly(void)
{
	unsigned int num_blocks;

	num_blocks = num_entries ?
		(num_entries + LINEINFO_BLOCK_ENTRIES - 1) / LINEINFO_BLOCK_ENTRIES : 0;

	printf("/* SPDX-License-Identifier: GPL-2.0 */\n");
	printf("/*\n");
	printf(" * Automatically generated by scripts/gen_lineinfo --module\n");
	printf(" * Do not edit.\n");
	printf(" */\n\n");

	printf("\t.section .mod_lineinfo, \"a\"\n\n");

	/*
	 * Header -- offsets and sizes are assembler expressions so the
	 * layout is self-describing without manual C arithmetic.
	 */
	printf(".Lhdr:\n");
	printf("\t.balign 4\n");
	printf("\t.long %u\t\t\t\t/* num_entries */\n", num_entries);
	printf("\t.long %u\t\t\t\t/* num_blocks */\n", num_blocks);
	printf("\t.long %u\t\t\t\t/* num_files */\n", num_files);
	printf("\t.long .Lblk_addrs - .Lhdr\t\t/* blocks_offset */\n");
	printf("\t.long .Lblk_offsets_end - .Lblk_addrs\t/* blocks_size */\n");
	printf("\t.long .Ldata - .Lhdr\t\t\t/* data_offset */\n");
	printf("\t.long .Ldata_end - .Ldata\t\t/* data_size */\n");
	printf("\t.long .Lfile_offsets - .Lhdr\t\t/* files_offset */\n");
	printf("\t.long .Lfile_offsets_end - .Lfile_offsets /* files_size */\n");
	printf("\t.long .Lfilenames - .Lhdr\t\t/* filenames_offset */\n");
	printf("\t.long .Lfilenames_end - .Lfilenames\t/* filenames_size */\n");
	printf("\t.long 0\t\t\t\t\t/* reserved */\n\n");

	/* block_addrs[] */
	printf(".Lblk_addrs:\n");
	for (unsigned int i = 0; i < num_blocks; i++)
		printf("\t.long 0x%x\n", entries[i * LINEINFO_BLOCK_ENTRIES].offset);

	/* block_offsets[] */
	printf(".Lblk_offsets:\n");
	for (unsigned int i = 0; i < num_blocks; i++)
		printf("\t.long .Lblock_%u - .Ldata\n", i);
	printf(".Lblk_offsets_end:\n\n");

	/* compressed data stream */
	printf(".Ldata:\n");
	for (unsigned int i = 0; i < num_blocks; i++) {
		printf(".Lblock_%u:\n", i);
		emit_block_data(i);
	}
	printf(".Ldata_end:\n");

	/* file_offsets[] */
	printf("\t.balign 4\n");
	printf(".Lfile_offsets:\n");
	for (unsigned int i = 0; i < num_files; i++)
		printf("\t.long %u\n", files[i].str_offset);
	printf(".Lfile_offsets_end:\n\n");

	/* filenames[] */
	printf(".Lfilenames:\n");
	for (unsigned int i = 0; i < num_files; i++)
		print_escaped_asciz(files[i].name);
	printf(".Lfilenames_end:\n");
}

int main(int argc, char *argv[])
{
	int fd;
	Elf *elf;
	Dwarf *dwarf;
	unsigned long long text_addr;

	if (argc >= 2 && !strcmp(argv[1], "--module")) {
		module_mode = 1;
		argv++;
		argc--;
	}

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [--module] <ELF file>\n", argv[0]);
		return 1;
	}

	/*
	 * For module mode, open O_RDWR so we can apply debug section
	 * relocations to the in-memory ELF data.  The modifications
	 * are NOT written back to disk (no elf_update() call).
	 */
	fd = open(argv[1], module_mode ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", argv[1],
			strerror(errno));
		return 1;
	}

	elf_version(EV_CURRENT);
	elf = elf_begin(fd, module_mode ? ELF_C_RDWR : ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin failed: %s\n",
			elf_errmsg(elf_errno()));
		close(fd);
		return 1;
	}

	if (module_mode) {
		/*
		 * .ko files are ET_REL after ld -r.  libdw does NOT apply
		 * relocations for ET_REL files, so DW_FORM_line_strp
		 * references in .debug_line are not resolved.  Apply them
		 * ourselves so that dwarf_linesrc() returns correct paths.
		 *
		 * DWARF addresses include the .text sh_addr.  Use .text
		 * sh_addr as the base so offsets are .text-relative.
		 */
		apply_debug_line_relocations(elf);
		find_text_section_range(elf);
		text_addr = text_section_start;
	} else {
		text_addr = find_text_addr(elf);
	}

	dwarf = dwarf_begin_elf(elf, DWARF_C_READ, NULL);
	if (!dwarf) {
		fprintf(stderr, "dwarf_begin_elf failed: %s\n",
			dwarf_errmsg(dwarf_errno()));
		fprintf(stderr, "Is %s built with CONFIG_DEBUG_INFO?\n",
			argv[1]);
		elf_end(elf);
		close(fd);
		return 1;
	}

	process_dwarf(dwarf, text_addr);

	if (skipped_overflow)
		fprintf(stderr,
			"lineinfo: warning: %u entries skipped (offset > 4 GiB from _text)\n",
			skipped_overflow);

	deduplicate();
	compute_file_offsets();

	fprintf(stderr, "lineinfo: %u entries, %u files, %u blocks\n",
		num_entries, num_files,
		num_entries ?
		(num_entries + LINEINFO_BLOCK_ENTRIES - 1) / LINEINFO_BLOCK_ENTRIES : 0);

	if (module_mode)
		output_module_assembly();
	else
		output_assembly();

	dwarf_end(dwarf);
	elf_end(elf);
	close(fd);

	/* Cleanup */
	free(entries);
	for (unsigned int i = 0; i < num_files; i++)
		free(files[i].name);
	free(files);
	return 0;
}
