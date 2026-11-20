/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_FMODRET_H
#define __RESOLVE_BTFIDS_FMODRET_H

#include <libelf.h>

struct btf;

/* Tag the functions of ELF which return errors in BTF */
int fmodret_tag(Elf *elf, struct btf *btf, int verbose);

#endif
