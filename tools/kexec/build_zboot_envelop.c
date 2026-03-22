// SPDX-License-Identifier: GPL-2.0
/*
 * build_zboot_envelop.c - Pack zboot image, initramfs and cmdline into an ELF file.
 *
 * Usage: build_zboot_envelop <zboot_image> <initramfs> <cmdline> [output.elf]
 *
 * Output ELF sections:
 *   .kernel     - zboot image (PE signature preserved, no padding)
 *   .initrd     - initramfs image
 *   .cmdline    - kernel command line string (NUL-terminated)
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "zboot_envelop.h"

#define DEFAULT_OUTPUT "zboot_image.elf"

/*
 * Section indices into the section header table.
 */
enum {
	SHN_UNDEF_IDX = 0,
	SHN_KERNEL_IDX = 1,
	SHN_INITRD_IDX = 2,
	SHN_CMDLINE_IDX = 3,
	SHN_SHSTRTAB_IDX = 4,
	SHN_NUM = 5,
};

/*
 * String table layout (offsets are fixed at compile time):
 *
 *   off 0  : '\0'           (mandatory empty string)
 *   off 1  : ".kernel\0"
 *   off 9  : ".initrd\0"
 *   off 17 : ".cmdline\0"
 *   off 26 : ".shstrtab\0"
 */
#define SHSTR_OFF_KERNEL 1
#define SHSTR_OFF_INITRD 9
#define SHSTR_OFF_CMDLINE 17
#define SHSTR_OFF_SHSTRTAB 26

#define SHSTRTAB_CONTENT \
    "\0" KERNEL_SECT_NAME \
    "\0" INITRD_SECT_NAME \
    "\0" CMDLINE_SECT_NAME \
    "\0.shstrtab"

/* sizeof() includes the final NUL from the string literal. */
#define SHSTRTAB_SIZE (sizeof(SHSTRTAB_CONTENT))

/*
 * struct input_file - holds a memory-mapped input file together with its size.
 * @data:	pointer to the mapped region (or NULL if not mmap'd)
 * @size:	exact byte size of the file
 * @fd:		open file descriptor (-1 when closed)
 */
struct input_file {
	const void *data;
	size_t size;
	int fd;
};

/*
 * align8 - round @off up to the next multiple of 8.
 */
static inline size_t align8(size_t off)
{
	return (off + 7) & ~(size_t)7;
}

/*
 * open_and_map - open @path read-only and mmap its entire content.
 *
 * Returns 0 on success, -1 on error (errno is set by the failing syscall and
 * a diagnostic is printed to stderr).
 */
static int open_and_map(const char *path, struct input_file *f)
{
	struct stat st;

	f->fd = open(path, O_RDONLY);
	if (f->fd < 0) {
		fprintf(stderr, "build_zboot_envelop: cannot open '%s': %s\n", path,
			strerror(errno));
		return -1;
	}

	if (fstat(f->fd, &st) < 0) {
		fprintf(stderr, "build_zboot_envelop: cannot stat '%s': %s\n", path,
			strerror(errno));
		goto err_close;
	}

	f->size = (size_t)st.st_size;
	f->data = mmap(NULL, f->size, PROT_READ, MAP_PRIVATE, f->fd, 0);
	if (f->data == MAP_FAILED) {
		fprintf(stderr, "build_zboot_envelop: cannot mmap '%s': %s\n", path,
			strerror(errno));
		goto err_close;
	}

	return 0;

err_close:
	close(f->fd);
	f->fd = -1;
	return -1;
}

static void close_and_unmap(struct input_file *f)
{
	if (f->data && f->data != MAP_FAILED)
		munmap((void *)f->data, f->size);
	if (f->fd >= 0)
		close(f->fd);
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= n;
	}
	return 0;
}

/*
 * write_padding - write @len zero bytes to @fd.
 *
 * Returns 0 on success, -1 on error.
 */
static int write_padding(int fd, size_t len)
{
	static const uint8_t zero[8];
	size_t chunk;
	ssize_t n;

	while (len > 0) {
		chunk = (len < sizeof(zero)) ? len : sizeof(zero);
		n = write(fd, zero, chunk);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		len -= n;
	}
	return 0;
}

/*
 * fill_shdr - populate a Elf64_Shdr for a SHT_PROGBITS section.
 *
 * @shdr:	section header to fill
 * @name_off:	offset of the section name inside .shstrtab
 * @offset:	file offset at which the section data begins
 * @size:	exact byte count of the section data (no padding included)
 * @flags:	section flags (e.g. SHF_ALLOC)
 */
static void fill_shdr(Elf64_Shdr *shdr, uint32_t name_off, uint64_t offset,
		      uint64_t size, uint64_t flags)
{
	memset(shdr, 0, sizeof(*shdr));
	shdr->sh_name = name_off;
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = flags;
	shdr->sh_offset = offset;
	shdr->sh_size = size;
	shdr->sh_addralign = 1;
}

int main(int argc, char *argv[])
{
	const char *kernel_path, *initrd_path, *cmdline, *output_path;
	struct input_file kernel = { NULL, 0, -1 };
	struct input_file initrd = { NULL, 0, -1 };
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdrs[SHN_NUM];
	size_t cmdline_size; /* includes terminating NUL */

	/*
	 * File layout (all section-data offsets are 8-byte aligned except
	 * .kernel which must start directly after the headers to guarantee
	 * that no byte is inserted before the PE signature):
	 *
	 *   [ELF header]          64 B
	 *   [Section headers]     SHN_NUM * sizeof(Elf64_Shdr)
	 *   [.kernel data]        kernel.size bytes  (NO internal padding)
	 *   <pad to 8B>
	 *   [.initrd data]        initrd.size bytes
	 *   <pad to 8B>
	 *   [.cmdline data]       cmdline_size bytes
	 *   <pad to 8B>
	 *   [.shstrtab data]      SHSTRTAB_SIZE bytes
	 */
	size_t off_shdrs, off_kernel, off_initrd, off_cmdline, off_shstrtab;
	size_t pad_after_kernel, pad_after_initrd, pad_after_cmdline;
	int outfd;
	int ret = EXIT_FAILURE;

	if (argc < 4 || argc > 5) {
		fprintf(stderr,
			"Usage: %s <zboot_image> <initramfs> <cmdline> "
			"[output.elf]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	kernel_path = argv[1];
	initrd_path = argv[2];
	cmdline = argv[3];
	output_path = (argc == 5) ? argv[4] : DEFAULT_OUTPUT;
	cmdline_size = strlen(cmdline) + 1; /* +1 for NUL terminator */

	/* ------------------------------------------------------------------ */
	/* 1. Map input files                                                  */
	/* ------------------------------------------------------------------ */
	if (open_and_map(kernel_path, &kernel) < 0)
		goto out;

	if (open_and_map(initrd_path, &initrd) < 0)
		goto out;

	/* Compute file layout */
	off_shdrs = sizeof(Elf64_Ehdr);
	off_kernel = off_shdrs + SHN_NUM * sizeof(Elf64_Shdr);

	/*
	 * .kernel must not contain any padding - its sh_size equals the
	 * exact file size so that any PE authenticode signature is intact.
	 * Alignment padding goes *after* the raw bytes, between sections.
	 */
	pad_after_kernel = 0;
	off_initrd = off_kernel + kernel.size + pad_after_kernel;

	pad_after_initrd =
		align8(off_initrd + initrd.size) - (off_initrd + initrd.size);
	off_cmdline = off_initrd + initrd.size + pad_after_initrd;

	pad_after_cmdline = align8(off_cmdline + cmdline_size) -
			    (off_cmdline + cmdline_size);
	off_shstrtab = off_cmdline + cmdline_size + pad_after_cmdline;

	memset(&ehdr, 0, sizeof(ehdr));

	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;

	ehdr.e_type = ET_EXEC;
	ehdr.e_machine = EM_AARCH64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(Elf64_Ehdr);
	ehdr.e_shentsize = sizeof(Elf64_Shdr);
	ehdr.e_shnum = SHN_NUM;
	ehdr.e_shoff = (Elf64_Off)off_shdrs;
	ehdr.e_shstrndx = SHN_SHSTRTAB_IDX;

	/* Build section headers */
	memset(shdrs, 0, sizeof(shdrs));

	/* [0] SHN_UNDEF - mandatory null entry */

	/* [1] .kernel */
	fill_shdr(&shdrs[SHN_KERNEL_IDX], SHSTR_OFF_KERNEL,
		  (uint64_t)off_kernel, (uint64_t)kernel.size, SHF_ALLOC);

	/* [2] .initrd */
	fill_shdr(&shdrs[SHN_INITRD_IDX], SHSTR_OFF_INITRD,
		  (uint64_t)off_initrd, (uint64_t)initrd.size, SHF_ALLOC);

	/* [3] .cmdline */
	fill_shdr(&shdrs[SHN_CMDLINE_IDX], SHSTR_OFF_CMDLINE,
		  (uint64_t)off_cmdline, (uint64_t)cmdline_size, SHF_ALLOC);

	/* [4] .shstrtab */
	memset(&shdrs[SHN_SHSTRTAB_IDX], 0, sizeof(Elf64_Shdr));
	shdrs[SHN_SHSTRTAB_IDX].sh_name = SHSTR_OFF_SHSTRTAB;
	shdrs[SHN_SHSTRTAB_IDX].sh_type = SHT_STRTAB;
	shdrs[SHN_SHSTRTAB_IDX].sh_offset = (Elf64_Off)off_shstrtab;
	shdrs[SHN_SHSTRTAB_IDX].sh_size = (uint64_t)SHSTRTAB_SIZE;
	shdrs[SHN_SHSTRTAB_IDX].sh_addralign = 1;

	outfd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (outfd < 0) {
		fprintf(stderr, "build_zboot_envelop: cannot create '%s': %s\n", output_path,
			strerror(errno));
		goto out;
	}

	if (write_all(outfd, &ehdr, sizeof(ehdr)) < 0)
		goto err_write;

	if (write_all(outfd, shdrs, sizeof(shdrs)) < 0)
		goto err_write;

	/* .kernel - raw bytes, no padding inside the section */
	if (write_all(outfd, kernel.data, kernel.size) < 0)
		goto err_write;
	if (write_padding(outfd, pad_after_kernel) < 0)
		goto err_write;

	/* .initrd */
	if (write_all(outfd, initrd.data, initrd.size) < 0)
		goto err_write;
	if (write_padding(outfd, pad_after_initrd) < 0)
		goto err_write;

	/* .cmdline - NUL-terminated string */
	if (write_all(outfd, cmdline, cmdline_size) < 0)
		goto err_write;
	if (write_padding(outfd, pad_after_cmdline) < 0)
		goto err_write;

	/* .shstrtab */
	if (write_all(outfd, SHSTRTAB_CONTENT, SHSTRTAB_SIZE) < 0)
		goto err_write;

	printf("build_zboot_envelop: wrote '%s'  (.kernel=%zuB  .initrd=%zuB  "
	       ".cmdline=%zuB)\n",
	       output_path, kernel.size, initrd.size, cmdline_size - 1);

	close(outfd);
	ret = EXIT_SUCCESS;
	goto out;

err_write:
	fprintf(stderr, "build_zboot_envelop: write error on '%s': %s\n", output_path,
		strerror(errno));
	close(outfd);
	unlink(output_path);

out:
	close_and_unmap(&kernel);
	close_and_unmap(&initrd);
	return ret;
}
