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
			struct page *page;
			void *page_addr;
			u64 file_off;
			bool may_fault;
		};
		struct {
			const char *data;
			u64 data_sz;
		};
	};
};

static void freader_init_from_file(struct freader *r, void *buf, u32 buf_sz,
				   struct address_space *mapping, bool may_fault)
{
	memset(r, 0, sizeof(*r));
	r->buf = buf;
	r->buf_sz = buf_sz;
	r->mapping = mapping;
	r->may_fault = may_fault;
}

static void freader_init_from_mem(struct freader *r, const char *data, u64 data_sz)
{
	memset(r, 0, sizeof(*r));
	r->data = data;
	r->data_sz = data_sz;
}

static void freader_put_page(struct freader *r)
{
	if (!r->page)
		return;
	kunmap_local(r->page_addr);
	put_page(r->page);
	r->page = NULL;
}

static int freader_get_page(struct freader *r, u64 file_off)
{
	pgoff_t pg_off = file_off >> PAGE_SHIFT;

	freader_put_page(r);

	r->page = find_get_page(r->mapping, pg_off);

	if (!r->page && r->may_fault) {
		struct folio *folio;

		folio = read_cache_folio(r->mapping, pg_off, NULL, NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		r->page = folio_file_page(folio, pg_off);
	}

	if (!r->page)
		return -EFAULT;	/* page not mapped */

	r->page_addr = kmap_local_page(r->page);
	r->file_off = file_off & PAGE_MASK;

	return 0;
}

static const void *freader_fetch(struct freader *r, u64 file_off, size_t sz)
{
	int err;

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

	/* check if we need to fetch a different page first */
	if (!r->page || file_off < r->file_off || file_off >= r->file_off + PAGE_SIZE) {
		err = freader_get_page(r, file_off);
		if (err) {
			r->err = err;
			return NULL;
		}
	}

	/* if requested data is crossing page boundaries, we have to copy
	 * everything into our local buffer to keep a simple linear memory
	 * access interface
	 */
	if (file_off + sz > r->file_off + PAGE_SIZE) {
		int part_sz = r->file_off + PAGE_SIZE - file_off;

		/* copy the part that resides in the current page */
		memcpy(r->buf, r->page_addr + (file_off - r->file_off), part_sz);

		/* fetch next page */
		err = freader_get_page(r, r->file_off + PAGE_SIZE);
		if (err) {
			r->err = err;
			return NULL;
		}

		/* copy the rest of requested data */
		memcpy(r->buf + part_sz, r->page_addr, sz - part_sz);

		return r->buf;
	}

	/* if data fits in a single page, just return direct pointer */
	return r->page_addr + (file_off - r->file_off);
}

static void freader_cleanup(struct freader *r)
{
	freader_put_page(r);
}

/*
 * Parse build id from the note segment. This logic can be shared between
 * 32-bit and 64-bit system, because Elf32_Nhdr and Elf64_Nhdr are
 * identical.
 */
static int parse_build_id_buf(struct freader *r,
			      unsigned char *build_id, __u32 *size,
			      u64 note_offs, Elf32_Word note_size)
{
	const char note_name[] = "GNU";
	const size_t note_name_sz = sizeof(note_name);
	u64 build_id_off, new_offs, note_end = note_offs + note_size;
	u32 build_id_sz;
	const Elf32_Nhdr *nhdr;
	const char *data;

	while (note_offs + sizeof(Elf32_Nhdr) < note_end) {
		nhdr = freader_fetch(r, note_offs, sizeof(Elf32_Nhdr) + note_name_sz);
		if (!nhdr)
			return r->err;

		if (nhdr->n_type == BUILD_ID &&
		    nhdr->n_namesz == note_name_sz &&
		    !strcmp((char *)(nhdr + 1), note_name) &&
		    nhdr->n_descsz > 0 &&
		    nhdr->n_descsz <= BUILD_ID_SIZE_MAX) {

			build_id_off = note_offs + sizeof(Elf32_Nhdr) + ALIGN(note_name_sz, 4);
			build_id_sz = nhdr->n_descsz;

			/* freader_fetch() will invalidate nhdr pointer */
			data = freader_fetch(r, build_id_off, build_id_sz);
			if (!data)
				return r->err;

			memcpy(build_id, data, build_id_sz);
			memset(build_id + build_id_sz, 0, BUILD_ID_SIZE_MAX - build_id_sz);
			if (size)
				*size = build_id_sz;
			return 0;
		}

		new_offs = note_offs + sizeof(Elf32_Nhdr) +
			   ALIGN(nhdr->n_namesz, 4) + ALIGN(nhdr->n_descsz, 4);
		if (new_offs <= note_offs)  /* overflow */
			break;
		note_offs = new_offs;
	}

	return -EINVAL;
}

static inline int parse_build_id(struct freader *r,
				 unsigned char *build_id,
				 __u32 *size,
				 u64 note_start_off,
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
	phnum = ehdr->e_phnum;
	phoff = READ_ONCE(ehdr->e_phoff);

	/* set upper bound on amount of segments (phdrs) we iterate */
	if (phnum > MAX_PHDR_CNT)
		phnum = MAX_PHDR_CNT;

	for (i = 0; i < phnum; ++i) {
		phdr = freader_fetch(r, phoff + i * sizeof(Elf32_Phdr), sizeof(Elf32_Phdr));
		if (!phdr)
			return r->err;

		if (phdr->p_type == PT_NOTE &&
		    !parse_build_id(r, build_id, size, phdr->p_offset, phdr->p_filesz))
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
	phnum = ehdr->e_phnum;
	phoff = READ_ONCE(ehdr->e_phoff);

	/* set upper bound on amount of segments (phdrs) we iterate */
	if (phnum > MAX_PHDR_CNT)
		phnum = MAX_PHDR_CNT;

	for (i = 0; i < phnum; ++i) {
		phdr = freader_fetch(r, phoff + i * sizeof(Elf64_Phdr), sizeof(Elf64_Phdr));
		if (!phdr)
			return r->err;

		if (phdr->p_type == PT_NOTE &&
		    !parse_build_id(r, build_id, size, phdr->p_offset, phdr->p_filesz))
			return 0;
	}

	return -EINVAL;
}

/* enough for Elf64_Ehdr, Elf64_Phdr, and all the smaller requests */
#define MAX_FREADER_BUF_SZ 64

static int __build_id_parse(struct vm_area_struct *vma, unsigned char *build_id,
			    __u32 *size, bool may_fault)
{
	const Elf32_Ehdr *ehdr;
	struct freader r;
	char buf[MAX_FREADER_BUF_SZ];
	int ret;

	/* only works for page backed storage  */
	if (!vma->vm_file)
		return -EINVAL;

	freader_init_from_file(&r, buf, sizeof(buf), vma->vm_file->f_mapping, may_fault);

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

/*
 * Parse build ID of ELF file mapped to vma
 * @vma:      vma object
 * @build_id: buffer to store build id, at least BUILD_ID_SIZE long
 * @size:     returns actual build id size in case of success
 *
 * Assumes no page fault can be taken, so if relevant portions of ELF file are
 * not already paged in, fetching of build ID fails.
 *
 * Return: 0 on success; negative error, otherwise
 */
int build_id_parse_nofault(struct vm_area_struct *vma, unsigned char *build_id, __u32 *size)
{
	return __build_id_parse(vma, build_id, size, false /* !may_fault */);
}

/*
 * Parse build ID of ELF file mapped to VMA
 * @vma:      vma object
 * @build_id: buffer to store build id, at least BUILD_ID_SIZE long
 * @size:     returns actual build id size in case of success
 *
 * Assumes faultable context and can cause page faults to bring in file data
 * into page cache.
 *
 * Return: 0 on success; negative error, otherwise
 */
int build_id_parse(struct vm_area_struct *vma, unsigned char *build_id, __u32 *size)
{
	return __build_id_parse(vma, build_id, size, true /* may_fault */);
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

	freader_init_from_mem(&r, buf, buf_size);

	return parse_build_id_buf(&r, build_id, NULL, 0, buf_size);
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
