/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_PATCH_H
#define _LINUX_BPF_PATCH_H 1

#include <linux/bpf.h>

struct bpf_patch {
	struct bpf_insn *insn;
	size_t capacity;
	size_t len;
	int err;
};

void bpf_patch_free(struct bpf_patch *patch);
size_t bpf_patch_len(const struct bpf_patch *patch);
int bpf_patch_err(const struct bpf_patch *patch);
void __bpf_patch_append(struct bpf_patch *patch, struct bpf_insn insn);
struct bpf_insn *bpf_patch_data(const struct bpf_patch *patch);

#define bpf_patch_append(patch, ...) ({ \
	struct bpf_insn insn[] = { __VA_ARGS__ }; \
	int i; \
	for (i = 0; i < ARRAY_SIZE(insn); i++) \
		__bpf_patch_append(patch, insn[i]); \
})

#endif
