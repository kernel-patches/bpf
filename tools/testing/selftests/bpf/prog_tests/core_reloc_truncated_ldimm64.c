// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <elf.h>
#include <test_progs.h>

#include "core_reloc_truncated_ldimm64.skel.h"

static bool truncate_ldimm64_prog(void *elf_data, size_t elf_sz, const char *prog_name)
{
	Elf64_Ehdr *ehdr = elf_data;
	Elf64_Shdr *shdrs;
	Elf64_Sym *syms;
	const char *strs;
	size_t i, j;

	if (elf_sz < sizeof(*ehdr) || ehdr->e_shoff > elf_sz ||
	    ehdr->e_shnum > (elf_sz - ehdr->e_shoff) / sizeof(*shdrs))
		return false;

	shdrs = elf_data + ehdr->e_shoff;
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_type != SHT_SYMTAB)
			continue;
		syms = elf_data + shdrs[i].sh_offset;
		strs = elf_data + shdrs[shdrs[i].sh_link].sh_offset;
		for (j = 0; j < shdrs[i].sh_size / sizeof(*syms); j++) {
			if (ELF64_ST_TYPE(syms[j].st_info) == STT_FUNC &&
			    !strcmp(strs + syms[j].st_name, prog_name)) {
				syms[j].st_size = sizeof(struct bpf_insn);
				return true;
			}
		}
	}

	return false;
}

static void run_test(const char *prog_name)
{
	const void *elf_bytes;
	size_t elf_sz;
	struct bpf_object *obj = NULL;
	void *elf_data = NULL;
	char *log = NULL;
	int err;

	elf_bytes = core_reloc_truncated_ldimm64__elf_bytes(&elf_sz);
	if (!ASSERT_OK_PTR(elf_bytes, "elf_bytes"))
		return;

	elf_data = malloc(elf_sz);
	if (!ASSERT_OK_PTR(elf_data, "elf_data"))
		return;
	memcpy(elf_data, elf_bytes, elf_sz);
	if (!ASSERT_TRUE(truncate_ldimm64_prog(elf_data, elf_sz, prog_name), "truncate_prog"))
		goto cleanup;

	obj = bpf_object__open_mem(elf_data, elf_sz, NULL);
	if (!ASSERT_OK_PTR(obj, "obj_open"))
		goto cleanup;

	if (start_libbpf_log_capture())
		goto cleanup;
	err = bpf_object__prepare(obj);
	log = stop_libbpf_log_capture();
	ASSERT_EQ(err, -EINVAL, "obj_prepare");
	ASSERT_HAS_SUBSTR(log, "insn #0 (LDIMM64) is truncated", "libbpf_log");

cleanup:
	free(log);
	bpf_object__close(obj);
	free(elf_data);
}

void test_core_reloc_truncated_ldimm64(void)
{
	if (test__start_subtest("resolved"))
		run_test("core_reloc_truncated_ldimm64_resolved");
	if (test__start_subtest("poison"))
		run_test("core_reloc_truncated_ldimm64_poison");
}
