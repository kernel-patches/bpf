/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_FMODRET_H
#define __RESOLVE_BTFIDS_FMODRET_H

#include <stdbool.h>
#include <stddef.h>
#include <libelf.h>
#include <linux/types.h>

struct btf;

/* A function found by the analysis, and the values it may return */
struct fmodret_retval {
	__u32 btf_id;
	char *values;
};

/* Sorted by BTF ID */
struct fmodret_retvals {
	struct fmodret_retval *retvals;
	size_t cnt, cap;
};

int fmodret_collect(Elf *elf, const struct btf *btf, struct fmodret_retvals *result,
		    bool patchable_ftrace, int verbose);
void fmodret_free(struct fmodret_retvals *retvals);

#endif
