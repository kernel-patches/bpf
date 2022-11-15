// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf_patch.h>

void bpf_patch_free(struct bpf_patch *patch)
{
	kfree(patch->insn);
}

size_t bpf_patch_len(const struct bpf_patch *patch)
{
	return patch->len;
}

int bpf_patch_err(const struct bpf_patch *patch)
{
	return patch->err;
}

void __bpf_patch_append(struct bpf_patch *patch, struct bpf_insn insn)
{
	void *arr;

	if (patch->err)
		return;

	if (patch->len + 1 > patch->capacity) {
		if (!patch->capacity)
			patch->capacity = 16;
		else
			patch->capacity *= 2;

		arr = krealloc_array(patch->insn, patch->capacity, sizeof(insn), GFP_KERNEL);
		if (!arr) {
			patch->err = -ENOMEM;
			kfree(patch->insn);
			return;
		}

		patch->insn = arr;
		patch->capacity *= 2;
	}

	patch->insn[patch->len++] = insn;
}
EXPORT_SYMBOL(__bpf_patch_append);

struct bpf_insn *bpf_patch_data(const struct bpf_patch *patch)
{
	return patch->insn;
}

void bpf_patch_resolve_jmp(struct bpf_patch *patch)
{
	int i;

	for (i = 0; i < patch->len; i++) {
		if (BPF_CLASS(patch->insn[i].code) != BPF_JMP)
			continue;

		if (patch->insn[i].off != S16_MAX)
			continue;

		patch->insn[i].off = patch->len - i - 1;
	}
}

u32 bpf_patch_magles_registers(const struct bpf_patch *patch)
{
	u32 mask = 0;
	int i;

	for (i = 0; i < patch->len; i++)
		mask |= 1 << patch->insn[i].dst_reg;

	return mask;
}
