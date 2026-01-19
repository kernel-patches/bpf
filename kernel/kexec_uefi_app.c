// SPDX-License-Identifier: GPL-2.0
/*
 * UEFI appilication file helpers
 *
 * Copyright (C) 2025, 2026 Red Hat, Inc
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/pe.h>
#include <linux/string.h>
#include "kexec_internal.h"

/*
 * The UEFI Terse Executable (TE) image has MZ header.
 */
static bool is_valid_pe(const char *kernel_buf, unsigned long kernel_len)
{
	struct mz_hdr *mz;
	struct pe_hdr *pe;

	if (!kernel_buf)
		return false;
	mz = (struct mz_hdr *)kernel_buf;
	if (mz->magic != IMAGE_DOS_SIGNATURE)
		return false;
	pe = (struct pe_hdr *)(kernel_buf + mz->peaddr);
	if (pe->magic != IMAGE_NT_SIGNATURE)
		return false;
	if (pe->opt_hdr_size == 0) {
		pr_err("optional header is missing\n");
		return false;
	}
	return true;
}

bool pe_has_bpf_section(const char *file_buf, unsigned long pe_sz)
{
	char *sect_start = NULL;
	unsigned long sect_sz = 0;
	int ret;

	if (!is_valid_pe(file_buf, pe_sz))
		return false;
	ret = pe_get_section(file_buf, ".bpf", &sect_start, &sect_sz);
	if (ret < 0)
		return false;
	return true;
}

int pe_get_section(const char *file_buf, const char *sect_name,
		char **sect_start, unsigned long *sect_sz)
{
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	struct section_header *sect_hdr;
	int section_nr, i;
	struct mz_hdr *mz = (struct mz_hdr *)file_buf;

	*sect_start = NULL;
	*sect_sz = 0;
	pe_hdr = (struct pe_hdr *)(file_buf + mz->peaddr);
	section_nr = pe_hdr->sections;
	opt_hdr = (struct pe32plus_opt_hdr *)(file_buf + mz->peaddr +
				sizeof(struct pe_hdr));
	sect_hdr = (struct section_header *)((char *)opt_hdr +
				pe_hdr->opt_hdr_size);

	for (i = 0; i < section_nr; i++) {
		if (strcmp(sect_hdr->name, sect_name) == 0) {
			*sect_start = (char *)file_buf + sect_hdr->data_addr;
			*sect_sz = sect_hdr->raw_data_size;
			return 0;
		}
		sect_hdr++;
	}

	return -1;
}
