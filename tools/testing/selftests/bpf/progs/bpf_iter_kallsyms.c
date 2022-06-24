// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Oracle and/or its affiliates. */
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

unsigned long last_sym_value = 0;

static inline char tolower(char c)
{
	if (c >= 'A' && c <= 'Z')
		c += ('a' - 'A');
	return c;
}

static inline char toupper(char c)
{
	if (c >= 'a' && c <= 'z')
		c -= ('a' - 'A');
	return c;
}

/* Dump symbols with max size; the latter is calculated by caching symbol N value
 * and when iterating on symbol N+1, we can print max size of symbol N via
 * address of N+1 - address of N.
 */
SEC("iter/kallsyms")
int dump_kallsyms(struct bpf_iter__kallsyms *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct kallsym_iter *iter = ctx->kallsym_iter;
	__u32 seq_num = ctx->meta->seq_num;
	char type;
	int ret;

	if (!iter)
		return 0;

	if (seq_num == 0) {
		BPF_SEQ_PRINTF(seq, "ADDR TYPE NAME MODULE_NAME KIND MAX_SIZE\n");
		return 0;
	}
	if (last_sym_value)
		BPF_SEQ_PRINTF(seq, "0x%x\n", iter->value - last_sym_value);
	else
		BPF_SEQ_PRINTF(seq, "\n");

	last_sym_value = iter->value;

	type = iter->type;

	if (iter->module_name[0]) {
		type = iter->exported ? toupper(type) : tolower(type);
		BPF_SEQ_PRINTF(seq, "0x%llx %c %s [ %s ] ",
			       iter->value, type, iter->name, iter->module_name);
	} else {
		BPF_SEQ_PRINTF(seq, "0x%llx %c %s ", iter->value, type, iter->name);
	}
	if (!iter->pos_arch_end || iter->pos_arch_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "CORE ");
	else if (!iter->pos_mod_end || iter->pos_mod_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "MOD ");
	else if (!iter->pos_ftrace_mod_end || iter->pos_ftrace_mod_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "FTRACE_MOD ");
	else if (!iter->pos_bpf_end || iter->pos_bpf_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "BPF ");
	else
		BPF_SEQ_PRINTF(seq, "KPROBE ");
	return 0;
}
