// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

#define ELFMAG "\177ELF"
#define SELFMAG 4
#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3
#define ET_CORE 4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff
#define EI_CLASS 4
#define ELFCLASS32 1
#define ELFCLASS64 2
#define STT_TLS 6

#define ELF_ST_BIND(x) ((x) >> 4)
#define ELF_ST_TYPE(x) ((x) & 0xf)
#define ELF32_ST_BIND(x) ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x) ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x) ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x) ELF_ST_TYPE(x)

char _license[] SEC("license") = "GPL";

int pid, err;
void *user_ptr;

char buf[1024];

static long process_vma(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	Elf64_Shdr symtab, strtab, tmp;
	const Elf64_Sym *symbol;
	int count, off, i, e_shnum, e_shoff, e_shentsize, sections = 0;
	const char *string;
	struct bpf_dynptr dynptr;
	const __u32 slen = 11;
	static const char *needle = "tls_counter";

	err = 0;
	if (!vma->vm_file)
		return 0;

	err = bpf_dynptr_from_file(vma->vm_file, buf, sizeof(buf), 0, &dynptr);
	if (err)
		goto fail;

	ehdr = (Elf64_Ehdr *)bpf_dynptr_slice(&dynptr, 0, buf, sizeof(Elf64_Ehdr));
	if (!ehdr)
		goto fail;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		goto fail;

	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		goto fail;

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		goto fail;

	/* Copy fields from ehdr, as nect call to slice invalidates it */
	e_shnum = ehdr->e_shnum;
	e_shoff = ehdr->e_shoff;
	e_shentsize = ehdr->e_shentsize;

	shdrs = bpf_dynptr_slice(&dynptr, e_shoff + e_shentsize * ehdr->e_shstrndx, buf,
				 sizeof(Elf64_Shdr));
	if (!shdrs)
		goto fail;

	off = shdrs->sh_offset;

	__builtin_memset(&symtab, 0, sizeof(symtab));
	__builtin_memset(&strtab, 0, sizeof(strtab));

	bpf_for(i, 0, e_shnum)
	{
		err = bpf_dynptr_read(&tmp, sizeof(Elf64_Shdr), &dynptr, e_shoff + e_shentsize * i,
				      0);
		if (err)
			goto fail;

		string = bpf_dynptr_slice(&dynptr, off + tmp.sh_name, buf, slen);
		if (!string)
			goto fail;

		if (bpf_strncmp(string, slen, ".symtab") == 0) {
			symtab = tmp;
			++sections;
		} else if (bpf_strncmp(string, slen, ".strtab") == 0) {
			strtab = tmp;
			++sections;
		}
		if (sections == 2)
			break;
	}
	if (sections != 2)
		goto fail;

	count = symtab.sh_size / sizeof(Elf64_Sym);
	bpf_for(i, 0, count)
	{
		symbol = bpf_dynptr_slice(&dynptr, symtab.sh_offset + sizeof(Elf64_Sym) * i, buf,
					  sizeof(Elf64_Sym));
		if (!symbol)
			goto fail;
		if (symbol->st_name == 0 || ELF64_ST_TYPE(symbol->st_info) != STT_TLS)
			continue;
		string = bpf_dynptr_slice(&dynptr, strtab.sh_offset + symbol->st_name, buf, slen);
		if (!string)
			goto fail;
		if (bpf_strncmp(string, slen, needle) == 0)
			goto success;
	}
fail:
	err = 1;
success:
	bpf_dynptr_file_discard(&dynptr);
	return err ? 1 : 0;
}

SEC("fentry.s/" SYS_PREFIX "sys_nanosleep")
int on_nanosleep(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	bpf_find_vma(task, (unsigned long)user_ptr, process_vma, NULL, 0);
	return 0;
}
