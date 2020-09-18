// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Oracle and/or its affiliates. */
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char _license[] SEC("license") = "GPL";

long tasks = 0;
long seq_err = 0;

/* struct task_struct's BTF representation will overflow PAGE_SIZE so cannot
 * be used here; instead dump a structure associated with each task.
 */
SEC("iter/task")
int dump_task_fs_struct(struct bpf_iter__task *ctx)
{
	static const char fs_type[] = "struct fs_struct";
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct fs_struct *fs = (void *)0;
	static struct btf_ptr ptr = { };
	long ret;

	if (task)
		fs = task->fs;

	ptr.type = fs_type;
	ptr.ptr = fs;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "Raw BTF fs_struct per task\n");

	ret = bpf_seq_btf_write(seq, &ptr, sizeof(ptr), 0);
	switch (ret) {
	case 0:
		tasks++;
		break;
	case -ERANGE:
		/* NULL task or task->fs, don't count it as an error. */
		break;
	default:
		seq_err = ret;
		break;
	}

	return 0;
}
