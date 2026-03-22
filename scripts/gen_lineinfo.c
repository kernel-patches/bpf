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

static unsigned int skipped_overflow;

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

	/* If already relative, use as-is */
	if (path[0] != '/')
		return path;

	/* comp_dir from DWARF is the most reliable method */
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

	/* Fall back to basename */
	p = strrchr(path, '/');
	return p ? p + 1 : path;
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

	/* Sorted address offsets from _text */
	printf("\t.globl lineinfo_addrs\n");
	printf("\t.balign 4\n");
	printf("lineinfo_addrs:\n");
	for (unsigned int i = 0; i < num_entries; i++)
		printf("\t.long 0x%x\n", entries[i].offset);
	printf("\n");

	/* File IDs, parallel to addrs (u16 -- supports up to 65535 files) */
	printf("\t.globl lineinfo_file_ids\n");
	printf("\t.balign 2\n");
	printf("lineinfo_file_ids:\n");
	for (unsigned int i = 0; i < num_entries; i++)
		printf("\t.short %u\n", entries[i].file_id);
	printf("\n");

	/* Line numbers, parallel to addrs */
	printf("\t.globl lineinfo_lines\n");
	printf("\t.balign 4\n");
	printf("lineinfo_lines:\n");
	for (unsigned int i = 0; i < num_entries; i++)
		printf("\t.long %u\n", entries[i].line);
	printf("\n");

	/* File string offset table */
	printf("\t.globl lineinfo_file_offsets\n");
	printf("\t.balign 4\n");
	printf("lineinfo_file_offsets:\n");
	for (unsigned int i = 0; i < num_files; i++)
		printf("\t.long %u\n", files[i].str_offset);
	printf("\n");

	/* Filenames size */
	{
		unsigned int fsize = 0;

		for (unsigned int i = 0; i < num_files; i++)
			fsize += strlen(files[i].name) + 1;
		printf("\t.globl lineinfo_filenames_size\n");
		printf("\t.balign 4\n");
		printf("lineinfo_filenames_size:\n");
		printf("\t.long %u\n\n", fsize);
	}

	/* Concatenated NUL-terminated filenames */
	printf("\t.globl lineinfo_filenames\n");
	printf("lineinfo_filenames:\n");
	for (unsigned int i = 0; i < num_files; i++)
		print_escaped_asciz(files[i].name);
	printf("\n");
}

int main(int argc, char *argv[])
{
	int fd;
	Elf *elf;
	Dwarf *dwarf;
	unsigned long long text_addr;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <vmlinux>\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", argv[1],
			strerror(errno));
		return 1;
	}

	elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin failed: %s\n",
			elf_errmsg(elf_errno()));
		close(fd);
		return 1;
	}

	text_addr = find_text_addr(elf);

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

	fprintf(stderr, "lineinfo: %u entries, %u files\n",
		num_entries, num_files);

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
