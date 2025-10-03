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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} arrmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10000000);
} ringbuf SEC(".maps");

struct elem {
	struct file *file;
	struct bpf_task_work tw;
};

enum file_reader_test {
	VALIDATE_LARGE_FILE = 1,
	SEARCH_ELF = 2,
};

int err;
void *user_ptr;
char buf[1024];
char *user_buf;
volatile const __u32 user_buf_sz;
volatile const __s32 test_type = -1;

static int process_vma(struct task_struct *task, struct vm_area_struct *vma, void *data);
static int search_elf(struct file *file);
static int validate_large_file_read(struct file *file);
static int task_work_callback(struct bpf_map *map, void *key, void *value);

SEC("raw_tp/sys_enter")
int on_getpid(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct elem *work;
	int key = 0;

	work = bpf_map_lookup_elem(&arrmap, &key);
	if (!work) {
		err = 1;
		return 0;
	}
	bpf_task_work_schedule_signal(task, &work->tw, &arrmap, task_work_callback, NULL);
	return 0;
}

static int task_work_callback(struct bpf_map *map, void *key, void *value)
{
	struct task_struct *task = bpf_get_current_task_btf();

	bpf_find_vma(task, (unsigned long)user_ptr, process_vma, NULL, 0);
	return 0;
}

static int process_vma(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	switch (test_type) {
	case VALIDATE_LARGE_FILE:
		err = validate_large_file_read(vma->vm_file);
		break;
	case SEARCH_ELF:
		err = search_elf(vma->vm_file);
		break;
	default:
		err = 1;
	}
	return err;
}

static int validate_large_file_read(struct file *file)
{
	struct bpf_dynptr dynptr;
	int err, i;
	char *rbuf1 = NULL, *rbuf2 = NULL;

	if (!file) {
		err = 1;
		return 1;
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err)
		goto cleanup_file;

	rbuf1 = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!rbuf1)
		goto cleanup_file;

	rbuf2 = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!rbuf2)
		goto cleanup_all;

	bpf_dynptr_read(rbuf1, user_buf_sz, &dynptr, 0, 0);
	bpf_copy_from_user(rbuf2, user_buf_sz, user_buf);
	/* Verify file contents read from BPF is the same as the one read from userspace */
	bpf_for(i, 0, user_buf_sz) {
		if (i >= 256000 || rbuf1[i] != rbuf2[i]) {
			err = 1;
			break;
		}
	}

cleanup_all:
	if (rbuf1)
		bpf_ringbuf_discard(rbuf1, 0);
	if (rbuf2)
		bpf_ringbuf_discard(rbuf2, 0);
cleanup_file:
	bpf_dynptr_file_discard(&dynptr);
	return err ? 1 : 0;
}

/* Finds thread local variable `tls_counter` in this executable's ELF */
static int search_elf(struct file *file)
{
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdrs;
	Elf64_Shdr symtab, strtab, tmp;
	const Elf64_Sym *symbol;
	int count, off, i, e_shnum, e_shoff, e_shentsize, sections = 0;
	const char *string;
	struct bpf_dynptr dynptr;
	const __u32 slen = 11;
	static const char *needle = "tls_counter";

	if (!file) {
		err = 1;
		return 1;
	}

	err = bpf_dynptr_from_file(file, 0, &dynptr);
	if (err)
		goto fail;

	err = bpf_dynptr_read(&ehdr, sizeof(ehdr), &dynptr, 0, 0);
	if (err)
		goto fail;

	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		goto fail;

	if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
		goto fail;

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64)
		goto fail;

	e_shnum = ehdr.e_shnum;
	e_shoff = ehdr.e_shoff;
	e_shentsize = ehdr.e_shentsize;

	err = bpf_dynptr_read(&shdrs, sizeof(shdrs), &dynptr,
			      e_shoff + e_shentsize * ehdr.e_shstrndx, 0);
	if (err)
		goto fail;

	off = shdrs.sh_offset;

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
