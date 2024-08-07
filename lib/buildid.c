// SPDX-License-Identifier: GPL-2.0

#include <linux/buildid.h>
#include <linux/cache.h>
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>

#define BUILD_ID 3

#define MAX_PHDR_CNT 256

struct freader {
	void *buf;
	u32 buf_sz;
	int err;
	union {
		struct {
			struct address_space *mapping;
			struct folio *folio;
			void *addr;
			loff_t folio_off;
		};
		struct {
			const char *data;
			u64 data_sz;
		};
	};
};

static void freader_init_from_file(struct freader *r, void *buf, u32 buf_sz,
				   struct address_space *mapping)
{
	memset(r, 0, sizeof(*r));
	r->buf = buf;
	r->buf_sz = buf_sz;
	r->mapping = mapping;
}

static void freader_init_from_mem(struct freader *r, const char *data, u64 data_sz)
{
	memset(r, 0, sizeof(*r));
	r->data = data;
	r->data_sz = data_sz;
}

static void freader_put_folio(struct freader *r)
{
	if (!r->folio)
		return;
	kunmap_local(r->addr);
	folio_put(r->folio);
	r->folio = NULL;
}

static int freader_get_folio(struct freader *r, loff_t file_off)
{
	/* check if we can just reuse current folio */
	if (r->folio && file_off >= r->folio_off &&
	    file_off < r->folio_off + folio_size(r->folio))
		return 0;

	freader_put_folio(r);

	r->folio = filemap_get_folio(r->mapping, file_off >> PAGE_SHIFT);
	if (IS_ERR(r->folio) || !folio_test_uptodate(r->folio)) {
		if (!IS_ERR(r->folio))
			folio_put(r->folio);
		r->folio = NULL;
		return -EFAULT;
	}

	r->folio_off = folio_pos(r->folio);
	r->addr = kmap_local_folio(r->folio, 0);

	return 0;
}

static const void *freader_fetch(struct freader *r, loff_t file_off, size_t sz)
{
	size_t folio_sz;

	/* provided internal temporary buffer should be sized correctly */
	if (WARN_ON(r->buf && sz > r->buf_sz)) {
		r->err = -E2BIG;
		return NULL;
	}

	if (unlikely(file_off + sz < file_off)) {
		r->err = -EOVERFLOW;
		return NULL;
	}

	/* working with memory buffer is much more straightforward */
	if (!r->buf) {
		if (file_off + sz > r->data_sz) {
			r->err = -ERANGE;
			return NULL;
		}
		return r->data + file_off;
	}

	/* fetch or reuse folio for given file offset */
	r->err = freader_get_folio(r, file_off);
	if (r->err)
		return NULL;

	/* if requested data is crossing folio boundaries, we have to copy
	 * everything into our local buffer to keep a simple linear memory
	 * access interface
	 */
	folio_sz = folio_size(r->folio);
	if (file_off + sz > r->folio_off + folio_sz) {
		int part_sz = r->folio_off + folio_sz - file_off;

		/* copy the part that resides in the current folio */
		memcpy(r->buf, r->addr + (file_off - r->folio_off), part_sz);

		/* fetch next folio */
		r->err = freader_get_folio(r, r->folio_off + folio_sz);
		if (r->err)
			return NULL;

		/* copy the rest of requested data */
		memcpy(r->buf + part_sz, r->addr, sz - part_sz);

		return r->buf;
	}

	/* if data fits in a single folio, just return direct pointer */
	return r->addr + (file_off - r->folio_off);
}

static void freader_cleanup(struct freader *r)
{
	if (!r->buf)
		return; /* non-file-backed mode */

	freader_put_folio(r);
}

/*
 * Parse build id from the note segment. This logic can be shared between
 * 32-bit and 64-bit system, because Elf32_Nhdr and Elf64_Nhdr are
 * identical.
 */
static int parse_build_id_buf(struct freader *r,
			      unsigned char *build_id, __u32 *size,
			      loff_t note_offs, Elf32_Word note_size)
{
	const char note_name[] = "GNU";
	const size_t note_name_sz = sizeof(note_name);
	const Elf32_Nhdr *nhdr;
	loff_t build_id_off, new_offs, note_end = note_offs + note_size;
	u32 name_sz, desc_sz;
	const char *data;

	while (note_end - note_offs > sizeof(Elf32_Nhdr) + note_name_sz) {
		nhdr = freader_fetch(r, note_offs, sizeof(Elf32_Nhdr) + note_name_sz);
		if (!nhdr)
			return r->err;

		name_sz = READ_ONCE(nhdr->n_namesz);
		desc_sz = READ_ONCE(nhdr->n_descsz);
		new_offs = note_offs + sizeof(Elf32_Nhdr) + ALIGN(name_sz, 4) + ALIGN(desc_sz, 4);
		if (new_offs <= note_offs /* overflow */ || new_offs > note_end)
			break;

		if (nhdr->n_type == BUILD_ID &&
		    name_sz == note_name_sz &&
		    strcmp((char *)(nhdr + 1), note_name) == 0 &&
		    desc_sz > 0 && desc_sz <= BUILD_ID_SIZE_MAX) {
			build_id_off = note_offs + sizeof(Elf32_Nhdr) + ALIGN(note_name_sz, 4);

			/* freader_fetch() will invalidate nhdr pointer */
			data = freader_fetch(r, build_id_off, desc_sz);
			if (!data)
				return r->err;

			memcpy(build_id, data, desc_sz);
			memset(build_id + desc_sz, 0, BUILD_ID_SIZE_MAX - desc_sz);
			if (size)
				*size = desc_sz;
			return 0;
		}

		note_offs = new_offs;
	}

	return -EINVAL;
}

static inline int parse_build_id(struct freader *r,
				 unsigned char *build_id,
				 __u32 *size,
				 loff_t note_start_off,
				 Elf32_Word note_size)
{
	/* check for overflow */
	if (note_start_off + note_size < note_start_off)
		return -EINVAL;

	/* only supports note that fits in the first page */
	if (note_start_off + note_size > PAGE_SIZE)
		return -EINVAL;

	return parse_build_id_buf(r, build_id, size, note_start_off, note_size);
}

/* Parse build ID from 32-bit ELF */
static int get_build_id_32(struct freader *r, unsigned char *build_id, __u32 *size)
{
	const Elf32_Ehdr *ehdr;
	const Elf32_Phdr *phdr;
	__u32 phnum, phoff, i;

	ehdr = freader_fetch(r, 0, sizeof(Elf32_Ehdr));
	if (!ehdr)
		return r->err;

	/* subsequent freader_fetch() calls invalidate pointers, so remember locally */
	phnum = READ_ONCE(ehdr->e_phnum);
	phoff = READ_ONCE(ehdr->e_phoff);

	/* set upper bound on amount of segments (phdrs) we iterate */
	if (phnum > MAX_PHDR_CNT)
		phnum = MAX_PHDR_CNT;

	/* check that phoff is not large enough to cause an overflow */
	if (phoff + phnum * sizeof(Elf32_Phdr) < phoff)
		return -EINVAL;

	for (i = 0; i < phnum; ++i) {
		phdr = freader_fetch(r, phoff + i * sizeof(Elf32_Phdr), sizeof(Elf32_Phdr));
		if (!phdr)
			return r->err;

		if (phdr->p_type == PT_NOTE &&
		    !parse_build_id(r, build_id, size, READ_ONCE(phdr->p_offset),
				    READ_ONCE(phdr->p_filesz)))
			return 0;
	}
	return -EINVAL;
}

/* Parse build ID from 64-bit ELF */
static int get_build_id_64(struct freader *r, unsigned char *build_id, __u32 *size)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Phdr *phdr;
	__u32 phnum, i;
	__u64 phoff;

	ehdr = freader_fetch(r, 0, sizeof(Elf64_Ehdr));
	if (!ehdr)
		return r->err;

	/* subsequent freader_fetch() calls invalidate pointers, so remember locally */
	phnum = READ_ONCE(ehdr->e_phnum);
	phoff = READ_ONCE(ehdr->e_phoff);

	/* set upper bound on amount of segments (phdrs) we iterate */
	if (phnum > MAX_PHDR_CNT)
		phnum = MAX_PHDR_CNT;

	/* check that phoff is not large enough to cause an overflow */
	if (phoff + phnum * sizeof(Elf64_Phdr) < phoff)
		return -EINVAL;

	for (i = 0; i < phnum; ++i) {
		phdr = freader_fetch(r, phoff + i * sizeof(Elf64_Phdr), sizeof(Elf64_Phdr));
		if (!phdr)
			return r->err;

		if (phdr->p_type == PT_NOTE &&
		    !parse_build_id(r, build_id, size, READ_ONCE(phdr->p_offset),
				    READ_ONCE(phdr->p_filesz)))
			return 0;
	}

	return -EINVAL;
}

/* enough for Elf64_Ehdr, Elf64_Phdr, and all the smaller requests */
#define MAX_FREADER_BUF_SZ 64

/*
 * Parse build ID of ELF file mapped to vma
 * @vma:      vma object
 * @build_id: buffer to store build id, at least BUILD_ID_SIZE long
 * @size:     returns actual build id size in case of success
 *
 * Return: 0 on success, -EINVAL otherwise
 */
int build_id_parse(struct vm_area_struct *vma, unsigned char *build_id,
		   __u32 *size)
{
	const Elf32_Ehdr *ehdr;
	struct freader r;
	char buf[MAX_FREADER_BUF_SZ];
	int ret;

	/* only works for page backed storage  */
	if (!vma->vm_file)
		return -EINVAL;

	freader_init_from_file(&r, buf, sizeof(buf), vma->vm_file->f_mapping);

	/* fetch first 18 bytes of ELF header for checks */
	ehdr = freader_fetch(&r, 0, offsetofend(Elf32_Ehdr, e_type));
	if (!ehdr) {
		ret = r.err;
		goto out;
	}

	ret = -EINVAL;

	/* compare magic x7f "ELF" */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/* only support executable file and shared object file */
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		goto out;

	if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
		ret = get_build_id_32(&r, build_id, size);
	else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
		ret = get_build_id_64(&r, build_id, size);
out:
	freader_cleanup(&r);
	return ret;
}

/**
 * build_id_parse_buf - Get build ID from a buffer
 * @buf:      ELF note section(s) to parse
 * @buf_size: Size of @buf in bytes
 * @build_id: Build ID parsed from @buf, at least BUILD_ID_SIZE_MAX long
 *
 * Return: 0 on success, -EINVAL otherwise
 */
int build_id_parse_buf(const void *buf, unsigned char *build_id, u32 buf_size)
{
	struct freader r;
	int err;

	freader_init_from_mem(&r, buf, buf_size);

	err = parse_build_id(&r, build_id, NULL, 0, buf_size);

	freader_cleanup(&r);
	return err;
}

#if IS_ENABLED(CONFIG_STACKTRACE_BUILD_ID) || IS_ENABLED(CONFIG_VMCORE_INFO)
unsigned char vmlinux_build_id[BUILD_ID_SIZE_MAX] __ro_after_init;

/**
 * init_vmlinux_build_id - Compute and stash the running kernel's build ID
 */
void __init init_vmlinux_build_id(void)
{
	extern const void __start_notes;
	extern const void __stop_notes;
	unsigned int size = &__stop_notes - &__start_notes;

	build_id_parse_buf(&__start_notes, vmlinux_build_id, size);
}
#endif
