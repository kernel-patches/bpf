// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Red Hat, Inc.
 * The zboot format carries the compressed kernel image offset and size
 * information in the DOS header. The program appends a bpf section to PE file,
 * meanwhile maintains the offset and size information, which is lost when using
 * objcopy to handle zboot image.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "pe.h"

#ifdef DEBUG_DETAIL
	#define dprintf(...) printf(__VA_ARGS__)
#else
	#define dprintf(...) ((void)0)
#endif

typedef struct {
	union {
		struct {
			unsigned int mz_magic;
			char image_type[4];
			/* offset to the whole file start */
			unsigned int payload_offset;
			unsigned int payload_size;
			unsigned int reserved[2];
			char comp_type[4];
		};
		char raw_bytes[56];
	};
	unsigned int linux_pe_magic;
	/* offset at: 0x3c or 60 */
	unsigned int pe_header_offset;
} __attribute__((packed)) pe_zboot_header;

typedef unsigned long	uintptr_t;
#define ALIGN_UP(p, size) (__typeof__(p))(((uintptr_t)(p) + ((size) - 1)) & ~((size) - 1))

int main(int argc, char **argv)
{
	uint32_t payload_new_offset, payload_sect_off;
	uint32_t payload_size;
	uint32_t payload_sect_idx;
	pe_zboot_header *zheader;
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	int base_fd, bpf_fd, out_fd;
	char *base_start_addr, *base_cur;
	char *out_start_addr, *out_cur;
	uint32_t out_sz, max_va_end = 0;
	struct stat sb;
	int i = 0, ret = 0;

	if (argc != 4) {
	    fprintf(stderr, "Usage: %s <original_pe> <binary_file> <new_pe>\n", argv[0]);
	    return -1;
	}

	const char *original_pe = argv[1];
	const char *binary_file = argv[2];
	const char *new_pe = argv[3];
	FILE *bin_fp = fopen(binary_file, "rb");
	if (!bin_fp) {
	    perror("Failed to open binary file");
	    return -1;
	}
	fseek(bin_fp, 0, SEEK_END);
	size_t bin_size = ftell(bin_fp);
	fseek(bin_fp, 0, SEEK_SET);
	base_fd = open(original_pe, O_RDWR);
	out_fd = open(new_pe, O_RDWR | O_CREAT, 0644);
	if (base_fd == -1 || out_fd == -1) {
	    perror("Error opening file");
	    exit(1);
	}

	if (fstat(base_fd, &sb) == -1) {
	    perror("Error getting file size");
	    exit(1);
	}
	base_start_addr = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, base_fd, 0);
	if (base_start_addr == MAP_FAILED) {
	    perror("Error mmapping the file");
	    exit(1);
	}
	/* 64KB for section table extending */
	out_sz = sb.st_size + bin_size + (1 << 16);
	out_start_addr = mmap(NULL, out_sz, PROT_WRITE, MAP_SHARED, out_fd, 0);
	if (ftruncate(out_fd, out_sz) == -1) {
		perror("Failed to resize output file");
		ret = -1;
		goto err;
	}
	if (out_start_addr == MAP_FAILED) {
	    perror("Error mmapping the file");
	    exit(1);
	}

	zheader = (pe_zboot_header *)base_start_addr;
	if (zheader->mz_magic != 0x5A4D) {  // 'MZ'
	    fprintf(stderr, "Invalid DOS signature\n");
	    return -1;
	}
	uint32_t pe_hdr_offset = get_pehdr_offset((const char *)base_start_addr);
	base_cur = base_start_addr + pe_hdr_offset;
	pe_hdr = (struct pe_hdr *)base_cur;
	if (pe_hdr->magic!= 0x00004550) {  // 'PE\0\0'
	    fprintf(stderr, "Invalid PE signature\n");
	    return -1;
	}
	base_cur += sizeof(struct pe_hdr);
	opt_hdr = (struct pe32plus_opt_hdr *)base_cur;
	uint32_t file_align = opt_hdr->file_align;
	uint32_t section_alignment = opt_hdr->section_align;

	uint16_t num_sections = pe_hdr->sections;
	struct section_header *base_sections, *sect;
	uint32_t section_table_offset = pe_hdr_offset + sizeof(struct pe_hdr) + pe_hdr->opt_hdr_size;
	base_sections = (struct section_header *)(base_start_addr + section_table_offset);

	/* Decide the section idx and the payload offset within the section */
	for (i = 0; i < num_sections; i++) {
	    sect = &base_sections[i];
	    if (zheader->payload_offset >= sect->data_addr &&
		zheader->payload_offset < (sect->data_addr + sect->raw_data_size)) {
		    payload_sect_idx = i;
		    payload_sect_off = zheader->payload_offset - sect->data_addr;
	    }
	}

	/* Calculate the end of the last section in virtual memory */
	for (i = 0; i < num_sections; i++) {
	    uint32_t section_end = base_sections[i].virtual_address + base_sections[i].virtual_size;
	    if (section_end > max_va_end) {
	        max_va_end = section_end;
	    }
	}

	/* Calculate virtual address for the new .bpf section */
	uint32_t bpf_virtual_address = ALIGN_UP(max_va_end, section_alignment);

	pe_zboot_header *new_zhdr = malloc(sizeof(pe_zboot_header));
	memcpy(new_zhdr, zheader, sizeof(pe_zboot_header));
	struct pe_hdr *new_hdr = malloc(sizeof(struct pe_hdr));
	memcpy(new_hdr, pe_hdr, sizeof(struct pe_hdr));
	new_hdr->sections += 1;
	struct pe32plus_opt_hdr *new_opt_hdr = malloc(pe_hdr->opt_hdr_size);
	memcpy(new_opt_hdr, opt_hdr, pe_hdr->opt_hdr_size);
	/* Create new section headers array (original + new section) */
	struct section_header *new_sections = calloc(1, new_hdr->sections * sizeof(struct section_header));
	if (!new_sections) {
	    perror("Failed to allocate memory for new section headers");
	    return -1;
	}
	memcpy(new_sections, base_sections, pe_hdr->sections * sizeof(struct section_header));

	/* Configure the new .bpf section */
	struct section_header *bpf_section = &new_sections[new_hdr->sections - 1];
	memset(bpf_section, 0, sizeof(struct section_header));
	strncpy((char *)bpf_section->name, ".bpf", 8);
	bpf_section->virtual_size = bin_size;
	bpf_section->virtual_address = bpf_virtual_address;
	bpf_section->raw_data_size = bin_size;
	bpf_section->flags = 0x40000000; //Readable

	/* Update headers */
	uint32_t new_size_of_image = bpf_section->virtual_address + bpf_section->virtual_size;
	new_size_of_image = ALIGN_UP(new_size_of_image, section_alignment);
	new_opt_hdr->image_size = new_size_of_image;

	size_t section_table_size = new_hdr->sections * (sizeof(struct section_header));
	size_t headers_size = section_table_offset + section_table_size;
	size_t aligned_headers_size = ALIGN_UP(headers_size, file_align);
	new_opt_hdr->header_size = aligned_headers_size;


	uint32_t current_offset = aligned_headers_size;
	/*
	 * If the original PE data_addr is covered by enlarged header_size
	 * re-assign new data_addr for all sections
	 */
	if (base_sections[0].data_addr < aligned_headers_size) {
		for (i = 0; i < new_hdr->sections; i++) {
		    new_sections[i].data_addr = current_offset;
		    current_offset += ALIGN_UP(new_sections[i].raw_data_size, file_align);
		}
	/* Keep unchanged, just allocating file pointer for bpf section */
	} else {
		uint32_t t;
		i = new_hdr->sections - 2;
		t = new_sections[i].data_addr + new_sections[i].raw_data_size;
		i++;
		new_sections[i].data_addr = ALIGN_UP(t, file_align);
	}

	payload_new_offset = new_sections[payload_sect_idx].data_addr + payload_sect_off;
	/* Update */
	new_zhdr->payload_offset = payload_new_offset;
	new_zhdr->payload_size = zheader->payload_size;
	dprintf("zboot payload_offset updated from 0x%x to 0x%x, size:0x%x\n",
		zheader->payload_offset, payload_new_offset, new_zhdr->payload_size);


	/* compose the new PE file */

	/* Write Dos header */
	memcpy(out_start_addr, new_zhdr, sizeof(pe_zboot_header));
	out_cur = out_start_addr + pe_hdr_offset;

	/* Write PE header */
	memcpy(out_cur, new_hdr, sizeof(struct pe_hdr));
	out_cur += sizeof(struct pe_hdr);

	/* Write PE optional header */
	memcpy(out_cur, new_opt_hdr, new_hdr->opt_hdr_size);
	out_cur += new_hdr->opt_hdr_size;

	/* Write all section headers */
	memcpy(out_cur, new_sections, new_hdr->sections * sizeof(struct section_header));

	/* Skip padding and copy the section data */
	for (i = 0; i < pe_hdr->sections; i++) {
		base_cur = base_start_addr + base_sections[i].data_addr;
		out_cur = out_start_addr + new_sections[i].data_addr;
		memcpy(out_cur, base_cur, base_sections[i].raw_data_size);
	}
	msync(out_start_addr, new_sections[i].data_addr + new_sections[i].raw_data_size, MS_ASYNC);
	/* For the bpf section */
	out_cur = out_start_addr + new_sections[i].data_addr;

	/* Write .bpf section data */
	char *bin_data = calloc(1, bin_size);
	if (!bin_data) {
		perror("Failed to allocate memory for binary data");
		free(base_sections);
		free(new_sections);
		ret = -1;
		goto err;
	}
	if (fread(bin_data, bin_size, 1, bin_fp) != 1) {
		perror("Failed to read binary data");
		free(bin_data);
		free(base_sections);
		free(new_sections);
		ret = -1;
		goto err;
	}

	if (out_cur + bin_size > out_start_addr + out_sz) {
	    perror("out of out_fd mmap\n");
	    ret = -1;
	    goto err;
	}
	memcpy(out_cur, bin_data, bin_size);
	/* calculate the real size */
	out_sz = out_cur + bin_size - out_start_addr;
	msync(out_start_addr, out_sz, MS_ASYNC);
	/* truncate to the real size */
	if (ftruncate(out_fd, out_sz) == -1) {
		perror("Failed to resize output file");
		ret = -1;
		goto err;
	}
	printf("Create a new PE file with bpf section: %s\n", new_pe);
err:
	munmap(out_start_addr, out_sz);
	munmap(base_start_addr, sb.st_size);
	close(base_fd);
	close(out_fd);
	close(bpf_fd);

	return ret;
}
