/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIBBPF_LIBBPF_ELF_H
#define __LIBBPF_LIBBPF_ELF_H

#include <libelf.h>

struct elf_fd {
	Elf *elf;
	int fd;
};

int elf_open(const char *binary_path, struct elf_fd *elf_fd);
void elf_close(struct elf_fd *elf_fd);

long elf_find_func_offset(Elf *elf, const char *binary_path, const char *name);
long elf_find_func_offset_from_file(const char *binary_path, const char *name);

#endif /* *__LIBBPF_LIBBPF_ELF_H */
