// SPDX-License-Identifier: GPL-2.0

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <test_progs.h>

#ifndef EM_BPF
#define EM_BPF 247
#endif

#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif

enum {
	SEC_NULL,
	SEC_TEXT,
	SEC_REL_TEXT,
	SEC_SYMTAB,
	SEC_STRTAB,
	SEC_SHSTRTAB,
	SEC_CNT,
};

enum {
	SHSTR_TEXT = 1,
	SHSTR_REL_TEXT = SHSTR_TEXT + sizeof(".text"),
	SHSTR_SYMTAB = SHSTR_REL_TEXT + sizeof(".rel.text"),
	SHSTR_STRTAB = SHSTR_SYMTAB + sizeof(".symtab"),
	SHSTR_SHSTRTAB = SHSTR_STRTAB + sizeof(".strtab"),
};

struct test_elf {
	void *buf;
	size_t sz;
};

static size_t elf_round_up(size_t value, size_t align)
{
	return (value + align - 1) / align * align;
}

static unsigned char elf_byteorder(void)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return ELFDATA2MSB;
#else
#error "Unrecognized __BYTE_ORDER__"
#endif
}

/*
 * Build a minimal ET_REL object in memory. A normal .bpf.c source cannot
 * produce a relocation whose offset points past the relocated section, so the
 * test constructs the ELF directly and feeds it to bpf_linker__add_buf().
 */
static struct test_elf make_relo_obj(size_t relo_off)
{
	static const char shstrtab[] = "\0.text\0.rel.text\0.symtab\0.strtab\0.shstrtab";
	static const char strtab[] = "\0";
	struct bpf_insn insns[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 0,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	size_t off, text_off, rel_off, symtab_off, strtab_off, shstrtab_off, shdr_off;
	struct test_elf obj = {};
	Elf64_Shdr *shdr;
	Elf64_Ehdr *ehdr;
	Elf64_Sym *sym;
	Elf64_Rel *rel;

	off = sizeof(*ehdr);
	text_off = elf_round_up(off, 8);
	off = text_off + sizeof(insns);
	rel_off = elf_round_up(off, 8);
	off = rel_off + sizeof(*rel);
	symtab_off = elf_round_up(off, 8);
	off = symtab_off + 2 * sizeof(*sym);
	strtab_off = off;
	off = strtab_off + sizeof(strtab);
	shstrtab_off = off;
	off = shstrtab_off + sizeof(shstrtab);
	shdr_off = elf_round_up(off, 8);
	off = shdr_off + SEC_CNT * sizeof(*shdr);

	obj.buf = calloc(1, off);
	if (!obj.buf)
		return obj;
	obj.sz = off;

	ehdr = obj.buf;
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = elf_byteorder();
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_type = ET_REL;
	ehdr->e_machine = EM_BPF;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_ehsize = sizeof(*ehdr);
	ehdr->e_shoff = shdr_off;
	ehdr->e_shentsize = sizeof(*shdr);
	ehdr->e_shnum = SEC_CNT;
	ehdr->e_shstrndx = SEC_SHSTRTAB;

	memcpy(obj.buf + text_off, insns, sizeof(insns));

	rel = obj.buf + rel_off;
	rel->r_offset = relo_off;
	rel->r_info = ELF64_R_INFO(1, R_BPF_64_64);

	sym = obj.buf + symtab_off;
	sym[1].st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
	sym[1].st_shndx = SEC_TEXT;

	memcpy(obj.buf + strtab_off, strtab, sizeof(strtab));
	memcpy(obj.buf + shstrtab_off, shstrtab, sizeof(shstrtab));

	shdr = obj.buf + shdr_off;
	shdr[SEC_TEXT] = (Elf64_Shdr) {
		.sh_name = SHSTR_TEXT,
		.sh_type = SHT_PROGBITS,
		.sh_flags = SHF_ALLOC | SHF_EXECINSTR,
		.sh_offset = text_off,
		.sh_size = sizeof(insns),
		.sh_addralign = 8,
		.sh_entsize = sizeof(struct bpf_insn),
	};
	shdr[SEC_REL_TEXT] = (Elf64_Shdr) {
		.sh_name = SHSTR_REL_TEXT,
		.sh_type = SHT_REL,
		.sh_offset = rel_off,
		.sh_size = sizeof(*rel),
		.sh_link = SEC_SYMTAB,
		.sh_info = SEC_TEXT,
		.sh_addralign = 8,
		.sh_entsize = sizeof(*rel),
	};
	shdr[SEC_SYMTAB] = (Elf64_Shdr) {
		.sh_name = SHSTR_SYMTAB,
		.sh_type = SHT_SYMTAB,
		.sh_offset = symtab_off,
		.sh_size = 2 * sizeof(*sym),
		.sh_link = SEC_STRTAB,
		.sh_info = 2,
		.sh_addralign = 8,
		.sh_entsize = sizeof(*sym),
	};
	shdr[SEC_STRTAB] = (Elf64_Shdr) {
		.sh_name = SHSTR_STRTAB,
		.sh_type = SHT_STRTAB,
		.sh_offset = strtab_off,
		.sh_size = sizeof(strtab),
		.sh_addralign = 1,
	};
	shdr[SEC_SHSTRTAB] = (Elf64_Shdr) {
		.sh_name = SHSTR_SHSTRTAB,
		.sh_type = SHT_STRTAB,
		.sh_offset = shstrtab_off,
		.sh_size = sizeof(shstrtab),
		.sh_addralign = 1,
	};

	return obj;
}

static int link_relo_obj(size_t relo_off)
{
	char path[] = "/tmp/libbpf_linker_relo_XXXXXX";
	struct test_elf obj = {};
	struct bpf_linker *linker;
	int err, fd;

	fd = mkstemp(path);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return -errno;
	close(fd);

	linker = bpf_linker__new(path, NULL);
	if (!ASSERT_OK_PTR(linker, "linker_new")) {
		err = libbpf_get_error(linker);
		goto out_unlink;
	}

	obj = make_relo_obj(relo_off);
	if (!ASSERT_OK_PTR(obj.buf, "make_relo_obj")) {
		err = -ENOMEM;
		goto out_free_linker;
	}

	err = bpf_linker__add_buf(linker, obj.buf, obj.sz, NULL);
	if (!err)
		err = bpf_linker__finalize(linker);

	free(obj.buf);
out_free_linker:
	bpf_linker__free(linker);
out_unlink:
	unlink(path);
	return err;
}

static void test_valid_relo_offset(void)
{
	ASSERT_OK(link_relo_obj(0), "valid_relo_offset");
}

static void test_invalid_relo_offset(void)
{
	ASSERT_EQ(link_relo_obj(0x1000), -EINVAL, "invalid_relo_offset");
}

void test_libbpf_linker(void)
{
	if (test__start_subtest("valid_relo_offset"))
		test_valid_relo_offset();
	if (test__start_subtest("invalid_relo_offset"))
		test_invalid_relo_offset();
}
