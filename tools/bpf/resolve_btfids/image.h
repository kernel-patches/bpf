/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_IMAGE_H
#define __RESOLVE_BTFIDS_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <gelf.h>

/*
 * The code of an ELF file, by address.
 *
 * In a linked image (vmlinux) an address is the virtual address and all fields
 * hold their final values. A relocatable file (a module) has neither: there the
 * address of a byte is the index of its section in the upper 32 bits and its
 * offset in the lower ones, and what a field refers to is taken from its
 * relocation. An undefined symbol lives in section 0, at 16 times its index.
 */
struct image_section {
	const char *name;
	/* Of a section with code */
	uint64_t addr, size;
	const unsigned char *data;
};

struct image_reloc {
	uint64_t addr;		/* of the field */
	uint64_t target;	/* symbol + addend */
};

/* A function of the file, or an undefined symbol of a relocatable file: no section, no size */
struct image_func {
	const char *name, *section;
	uint64_t addr, size;
};

struct image {
	Elf *elf;
	bool relocatable;
	struct image_section *sections;
	size_t nr_sections;
	struct image_reloc *relocs;	/* sorted by address */
	size_t nr_relocs;
	struct image_func *funcs;	/* sorted by name */
	size_t nr_funcs;
	Elf_Data *symbols;
	size_t nr_symbols, strndx;
};

int image_open(struct image *img, Elf *elf);
void image_close(struct image *img);

/* Return the address of the symbol NAME, or 0 */
uint64_t image_symbol(const struct image *img, const char *name);
/* Return the function NAME, or NULL if there is none or more than one */
const struct image_func *image_func(const struct image *img, const char *name);
/* Return the bytes at ADDR and set AVAIL to how many follow in the section */
const unsigned char *image_bytes(const struct image *img, uint64_t addr, size_t *avail);
/* Return the relocation of a field in the LEN bytes at ADDR, or NULL */
const struct image_reloc *image_reloc(const struct image *img, uint64_t addr, size_t len);

#endif
