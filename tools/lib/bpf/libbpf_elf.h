/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIBBPF_LIBBPF_ELF_H
#define __LIBBPF_LIBBPF_ELF_H

#include <libelf.h>

long elf_find_func_offset(Elf *elf, const char *binary_path, const char *name);
long elf_find_func_offset_from_file(const char *binary_path, const char *name);

#endif /* *__LIBBPF_LIBBPF_ELF_H */
