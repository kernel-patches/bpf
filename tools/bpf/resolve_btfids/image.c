// SPDX-License-Identifier: GPL-2.0-only
/* The code of an ELF file, by address. See image.h */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "image.h"

static uint64_t image_address(const struct image *img, size_t shndx, uint64_t value)
{
	return img->relocatable ? (uint64_t)shndx << 32 | value : value;
}

static uint64_t symbol_address(const struct image *img, size_t idx, const GElf_Sym *sym)
{
	if (sym->st_shndx == SHN_UNDEF)
		return img->relocatable ? idx << 4 : 0;
	if (sym->st_shndx >= SHN_LORESERVE)
		return 0;
	return image_address(img, sym->st_shndx, sym->st_value);
}

uint64_t image_symbol(const struct image *img, const char *name)
{
	size_t i;

	for (i = 1; i < img->nr_symbols; i++) {
		const char *s;
		GElf_Sym sym;

		if (!gelf_getsym(img->symbols, i, &sym) || !sym.st_name)
			continue;
		s = elf_strptr(img->elf, img->strndx, sym.st_name);
		if (s && !strcmp(s, name))
			return symbol_address(img, i, &sym);
	}
	return 0;
}

static int cmp_func(const void *va, const void *vb)
{
	const struct image_func *a = va, *b = vb;

	return strcmp(a->name, b->name);
}

const struct image_func *image_func(const struct image *img, const char *name)
{
	const struct image_func key = { .name = name }, *end = img->funcs + img->nr_funcs, *f;

	f = bsearch(&key, img->funcs, img->nr_funcs, sizeof(*f), cmp_func);
	if (!f || (f > img->funcs && !strcmp(f[-1].name, name)) ||
	    (f + 1 < end && !strcmp(f[1].name, name)))
		return NULL;
	return f;
}

const unsigned char *image_bytes(const struct image *img, uint64_t addr, size_t *avail)
{
	const struct image_section *s;
	size_t i;

	for (i = img->relocatable ? addr >> 32 : 1; i < img->nr_sections; i++) {
		s = &img->sections[i];
		if (addr - s->addr < s->size) {
			*avail = s->size - (addr - s->addr);
			return s->data + (addr - s->addr);
		}
	}
	return NULL;
}

const struct image_reloc *image_reloc(const struct image *img, uint64_t addr, size_t len)
{
	size_t lo = 0, hi = img->nr_relocs;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (img->relocs[mid].addr < addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < img->nr_relocs && img->relocs[lo].addr - addr < len ? &img->relocs[lo] : NULL;
}

static int cmp_reloc(const void *va, const void *vb)
{
	const struct image_reloc *a = va, *b = vb;

	return a->addr > b->addr ? 1 : a->addr < b->addr ? -1 : 0;
}

static int read_relocs(struct image *img, Elf_Scn *scn, const GElf_Shdr *shdr)
{
	size_t nr = shdr->sh_size / shdr->sh_entsize, i;
	Elf_Data *data = elf_getdata(scn, NULL);
	struct image_reloc *relocs;

	if (!data)
		return -EINVAL;
	relocs = realloc(img->relocs, (img->nr_relocs + nr) * sizeof(*relocs));
	if (!relocs)
		return -ENOMEM;
	img->relocs = relocs;
	for (i = 0; i < nr; i++) {
		GElf_Rela rela;
		GElf_Sym sym;
		uint64_t s;

		if (!gelf_getrela(data, i, &rela) ||
		    !gelf_getsym(img->symbols, GELF_R_SYM(rela.r_info), &sym))
			return -EINVAL;
		s = symbol_address(img, GELF_R_SYM(rela.r_info), &sym);
		if (!s)
			continue;
		relocs[img->nr_relocs].addr = image_address(img, shdr->sh_info, rela.r_offset);
		relocs[img->nr_relocs++].target = s + rela.r_addend;
	}
	return 0;
}

static int read_funcs(struct image *img)
{
	size_t i;

	img->funcs = calloc(img->nr_symbols, sizeof(*img->funcs));
	if (!img->funcs)
		return -ENOMEM;
	for (i = 1; i < img->nr_symbols; i++) {
		struct image_func *f = &img->funcs[img->nr_funcs];
		GElf_Sym sym;

		if (!gelf_getsym(img->symbols, i, &sym))
			return -EINVAL;
		if (sym.st_shndx == SHN_UNDEF ? !img->relocatable :
		    GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_shndx >= img->nr_sections)
			continue;
		f->name = elf_strptr(img->elf, img->strndx, sym.st_name);
		if (!f->name)
			return -EINVAL;
		f->section = img->sections[sym.st_shndx].name ?: "";
		f->addr = symbol_address(img, i, &sym);
		f->size = sym.st_size;
		img->nr_funcs++;
	}
	qsort(img->funcs, img->nr_funcs, sizeof(*img->funcs), cmp_func);
	return 0;
}

int image_open(struct image *img, Elf *elf)
{
	size_t i, shstrndx;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Scn *scn;
	int err;

	memset(img, 0, sizeof(*img));
	if (!gelf_getehdr(elf, &ehdr) || elf_getshdrnum(elf, &img->nr_sections) ||
	    elf_getshdrstrndx(elf, &shstrndx))
		return -EINVAL;
	img->elf = elf;
	img->relocatable = ehdr.e_type == ET_REL;
	img->sections = calloc(img->nr_sections, sizeof(*img->sections));
	if (!img->sections)
		return -ENOMEM;

	for (i = 1; i < img->nr_sections; i++) {
		struct image_section *s = &img->sections[i];
		Elf_Data *data;

		scn = elf_getscn(elf, i);
		if (!scn || !gelf_getshdr(scn, &shdr))
			return -EINVAL;
		s->name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!s->name)
			return -EINVAL;
		if (shdr.sh_type == SHT_SYMTAB) {
			img->symbols = elf_getdata(scn, NULL);
			img->nr_symbols = shdr.sh_size / shdr.sh_entsize;
			img->strndx = shdr.sh_link;
		}
		if (!(shdr.sh_flags & SHF_EXECINSTR) || shdr.sh_type != SHT_PROGBITS)
			continue;
		data = elf_getdata(scn, NULL);
		if (!data || data->d_size != shdr.sh_size)
			return -EINVAL;
		s->data = data->d_buf;
		s->addr = image_address(img, i, shdr.sh_addr);
		s->size = shdr.sh_size;
	}
	if (!img->symbols)
		return -EINVAL;
	err = read_funcs(img);
	if (err)
		return err;

	for (i = 1; img->relocatable && i < img->nr_sections; i++) {
		scn = elf_getscn(elf, i);
		if (!gelf_getshdr(scn, &shdr))
			return -EINVAL;
		if (shdr.sh_type != SHT_RELA || !img->sections[shdr.sh_info].size)
			continue;
		err = read_relocs(img, scn, &shdr);
		if (err)
			return err;
	}
	if (img->nr_relocs)
		qsort(img->relocs, img->nr_relocs, sizeof(*img->relocs), cmp_reloc);
	return 0;
}

void image_close(struct image *img)
{
	free(img->sections);
	free(img->relocs);
	free(img->funcs);
	memset(img, 0, sizeof(*img));
}
