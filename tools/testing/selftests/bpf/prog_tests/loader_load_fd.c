// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Google LLC */

#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <libelf.h>
#include <gelf.h>
#include <linux/bpf.h>

#include "bpf/skel_internal.h"
#include "test_loader_processed.lskel.h"

/* Test helper to create an in-memory ELF */
static int create_loader_elf(const void *insns, size_t insns_sz,
			     const void *map_data, size_t map_data_sz,
			     const char *license, size_t license_sz,
			     bool omit_prog, bool omit_map, bool omit_license)
{
	char shstrtab[] = "\0__loader.prog\0__loader.map\0license\0.shstrtab";
	size_t prog_off = 1;
	size_t map_off = prog_off + strlen("__loader.prog") + 1;
	size_t lic_off = map_off + strlen("__loader.map") + 1;
	size_t shstr_off = lic_off + strlen("license") + 1;
	size_t shstrtab_sz = sizeof(shstrtab);
	Elf_Data *shstr_data, *data;
	Elf64_Shdr *shstr_shdr, *shdr;
	Elf_Scn *shstr_scn, *scn;
	Elf64_Ehdr *ehdr;
	Elf *elf;
	int fd;

	fd = memfd_create("loader_elf", 0);
	if (!ASSERT_GE(fd, 0, "memfd_create"))
		return -1;

	elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!ASSERT_OK_PTR(elf, "elf_begin")) {
		close(fd);
		return -1;
	}

	ehdr = elf64_newehdr(elf);
	if (!ASSERT_OK_PTR(ehdr, "elf64_newehdr"))
		goto err;

	ehdr->e_ident[EI_MAG0] = ELFMAG0;
	ehdr->e_ident[EI_MAG1] = ELFMAG1;
	ehdr->e_ident[EI_MAG2] = ELFMAG2;
	ehdr->e_ident[EI_MAG3] = ELFMAG3;
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_machine = EM_BPF;
	ehdr->e_type = ET_REL;
	ehdr->e_version = EV_CURRENT;

	shstr_scn = elf_newscn(elf);
	shstr_shdr = elf64_getshdr(shstr_scn);
	shstr_shdr->sh_name = shstr_off;
	shstr_shdr->sh_type = SHT_STRTAB;
	shstr_shdr->sh_flags = 0;

	shstr_data = elf_newdata(shstr_scn);
	shstr_data->d_buf = shstrtab;
	shstr_data->d_size = shstrtab_sz;
	shstr_data->d_type = ELF_T_BYTE;
	shstr_data->d_align = 1;

	ehdr->e_shstrndx = elf_ndxscn(shstr_scn);

	if (!omit_prog && insns && insns_sz > 0) {
		scn = elf_newscn(elf);
		shdr = elf64_getshdr(scn);
		shdr->sh_name = prog_off;
		shdr->sh_type = SHT_PROGBITS;
		shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;

		data = elf_newdata(scn);
		data->d_buf = (void *)insns;
		data->d_size = insns_sz;
		data->d_type = ELF_T_BYTE;
		data->d_align = 8;
	}

	if (!omit_map && map_data && map_data_sz > 0) {
		scn = elf_newscn(elf);
		shdr = elf64_getshdr(scn);
		shdr->sh_name = map_off;
		shdr->sh_type = SHT_PROGBITS;
		shdr->sh_flags = SHF_ALLOC;

		data = elf_newdata(scn);
		data->d_buf = (void *)map_data;
		data->d_size = map_data_sz;
		data->d_type = ELF_T_BYTE;
		data->d_align = 8;
	}

	if (!omit_license && license && license_sz > 0) {
		scn = elf_newscn(elf);
		shdr = elf64_getshdr(scn);
		shdr->sh_name = lic_off;
		shdr->sh_type = SHT_PROGBITS;
		shdr->sh_flags = 0;

		data = elf_newdata(scn);
		data->d_buf = (void *)license;
		data->d_size = license_sz;
		data->d_type = ELF_T_BYTE;
		data->d_align = 1;
	}

	if (elf_update(elf, ELF_C_WRITE) < 0)
		goto err;

	elf_end(elf);
	lseek(fd, 0, SEEK_SET);
	return fd;

err:
	elf_end(elf);
	close(fd);
	return -1;
}

static int sys_bpf_loader_load_fd(int loader_fd, void *ctx, __u32 ctx_size)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.load_fd.loader_fd = loader_fd;
	attr.load_fd.ctx = ptr_to_u64(ctx);
	attr.load_fd.ctx_size = ctx_size;

	return syscall(__NR_bpf, BPF_LOADER_LOAD_FD, &attr, sizeof(attr));
}

static void test_loader_load_fd_invalid_fd(void)
{
	struct bpf_loader_ctx ctx = {};
	int err;

	err = sys_bpf_loader_load_fd(-1, &ctx, sizeof(ctx));
	ASSERT_EQ(err, -1, "invalid fd sys_bpf return");
	ASSERT_EQ(errno, EINVAL, "invalid fd errno");
}

static void test_loader_load_fd_oversized_ctx(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	char map_data[] = "data";
	char license[] = "GPL";
	struct bpf_loader_ctx ctx = {};
	int elf_fd, err;

	elf_fd = create_loader_elf(insns, sizeof(insns),
				   map_data, sizeof(map_data),
				   license, sizeof(license),
				   false, false, false);

	if (!ASSERT_GE(elf_fd, 0, "create_loader_elf"))
		return;

	err = sys_bpf_loader_load_fd(elf_fd, &ctx, 65536U);
	ASSERT_EQ(err, -1, "oversized ctx sys_bpf return");
	ASSERT_EQ(errno, EINVAL, "oversized ctx errno");

	close(elf_fd);
}

static void test_loader_load_fd_invalid_elf(void)
{
	char garbage[] = "not_an_elf_file_content";
	struct bpf_loader_ctx ctx = {};
	int fd, err;

	fd = memfd_create("garbage_file", 0);
	if (!ASSERT_GE(fd, 0, "memfd_create"))
		return;

	if (!ASSERT_EQ(write(fd, garbage, sizeof(garbage)), sizeof(garbage), "write garbage")) {
		close(fd);
		return;
	}
	lseek(fd, 0, SEEK_SET);

	err = sys_bpf_loader_load_fd(fd, &ctx, sizeof(ctx));
	ASSERT_EQ(err, -1, "invalid elf sys_bpf return");
	ASSERT_EQ(errno, ENOEXEC, "invalid elf errno");

	close(fd);
}

static void test_loader_load_fd_missing_prog_sec(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	char map_data[] = "data";
	char license[] = "GPL";
	struct bpf_loader_ctx ctx = {};
	int elf_fd, err;

	elf_fd = create_loader_elf(insns, sizeof(insns),
				   map_data, sizeof(map_data),
				   license, sizeof(license),
				   true, false, false);
	if (!ASSERT_GE(elf_fd, 0, "create_loader_elf"))
		return;

	err = sys_bpf_loader_load_fd(elf_fd, &ctx, sizeof(ctx));
	ASSERT_EQ(err, -1, "missing prog sec sys_bpf return");
	ASSERT_EQ(errno, EINVAL, "missing prog sec errno");

	close(elf_fd);
}

static void test_loader_load_fd_missing_map_sec(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	char map_data[] = "data";
	char license[] = "GPL";
	struct bpf_loader_ctx ctx = {};
	int elf_fd, err;

	elf_fd = create_loader_elf(insns, sizeof(insns),
				   map_data, sizeof(map_data),
				   license, sizeof(license),
				   false, true, false);
	if (!ASSERT_GE(elf_fd, 0, "create_loader_elf"))
		return;

	err = sys_bpf_loader_load_fd(elf_fd, &ctx, sizeof(ctx));
	ASSERT_EQ(err, -1, "missing map sec sys_bpf return");
	ASSERT_EQ(errno, EINVAL, "missing map sec errno");

	close(elf_fd);
}

static void test_loader_load_fd_missing_license_sec(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	char map_data[] = "data";
	char license[] = "GPL";
	struct bpf_loader_ctx ctx = {};
	int elf_fd, err;

	elf_fd = create_loader_elf(insns, sizeof(insns),
				   map_data, sizeof(map_data),
				   license, sizeof(license),
				   false, false, true);
	if (!ASSERT_GE(elf_fd, 0, "create_loader_elf"))
		return;

	err = sys_bpf_loader_load_fd(elf_fd, &ctx, sizeof(ctx));
	ASSERT_EQ(err, -1, "missing license sec sys_bpf return");
	ASSERT_EQ(errno, EINVAL, "missing license sec errno");

	close(elf_fd);
}

static void test_loader_load_fd_loader_failure(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, -EPERM),
		BPF_EXIT_INSN(),
	};
	char map_data[] = "data";
	char license[] = "GPL";
	struct bpf_loader_ctx ctx = {};
	int elf_fd, err;

	elf_fd = create_loader_elf(insns, sizeof(insns),
				   map_data, sizeof(map_data),
				   license, sizeof(license),
				   false, false, false);
	if (!ASSERT_GE(elf_fd, 0, "create_loader_elf"))
		return;

	err = sys_bpf_loader_load_fd(elf_fd, &ctx, sizeof(ctx));
	ASSERT_EQ(err, -1, "loader failure sys_bpf return");
	ASSERT_EQ(errno, EPERM, "loader failure errno");

	close(elf_fd);
}

struct test_loader_lskel {
	struct bpf_loader_ctx ctx;
	struct {
		struct bpf_map_desc test_map;
	} maps;
	struct {
		struct bpf_prog_desc probe;
	} progs;
	struct {
		int probe_fd;
	} links;
};

static void test_loader_load_fd_lskel(void)
{
	struct test_loader_lskel skel = {};
	int elf_fd, err;

	skel.ctx.sz = (char *)&skel.links - (char *)&skel;

	/* Build fake ELF using extracted opts_insn (__loader.prog) and opts_data (__loader.map) */
	elf_fd = create_loader_elf(test_loader_opts_insn, test_loader_opts_insn_sz,
				   test_loader_opts_data, test_loader_opts_data_sz,
				   "GPL", sizeof("GPL"),
				   false, false, false);
	if (!ASSERT_GE(elf_fd, 0, "create_loader_elf_lskel"))
		return;

	err = sys_bpf_loader_load_fd(elf_fd, &skel.ctx, skel.ctx.sz);
	ASSERT_OK(err, "sys_bpf_loader_load_fd lskel");

	ASSERT_GT(skel.progs.probe.prog_fd, 0, "test_loader probe prog_fd > 0");
	ASSERT_GT(skel.maps.test_map.map_fd, 0, "test_loader test_map map_fd > 0");

	if (skel.progs.probe.prog_fd > 0)
		close(skel.progs.probe.prog_fd);
	if (skel.maps.test_map.map_fd > 0)
		close(skel.maps.test_map.map_fd);
	close(elf_fd);
}

void test_loader_load_fd(void)
{
	if (test__start_subtest("invalid_fd"))
		test_loader_load_fd_invalid_fd();
	if (test__start_subtest("oversized_ctx"))
		test_loader_load_fd_oversized_ctx();
	if (test__start_subtest("invalid_elf"))
		test_loader_load_fd_invalid_elf();
	if (test__start_subtest("missing_prog_sec"))
		test_loader_load_fd_missing_prog_sec();
	if (test__start_subtest("missing_map_sec"))
		test_loader_load_fd_missing_map_sec();
	if (test__start_subtest("missing_license_sec"))
		test_loader_load_fd_missing_license_sec();
	if (test__start_subtest("loader_failure"))
		test_loader_load_fd_loader_failure();
	if (test__start_subtest("lskel"))
		test_loader_load_fd_lskel();
}
