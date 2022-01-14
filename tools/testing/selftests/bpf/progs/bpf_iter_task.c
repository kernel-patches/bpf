// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	static char info[] = "    === END ===";

	if (task == (void *)0) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "    tgid      gid\n");

	BPF_SEQ_PRINTF(seq, "%8d %8d\n", task->tgid, task->pid);
	return 0;
}

// New helper added
static long (*bpf_access_process_vm)(
	struct task_struct *tsk,
	unsigned long addr,
	void *buf,
	int len,
	unsigned int gup_flags) = (void *)186;

// Copied from include/linux/mm.h
#define FOLL_REMOTE 0x2000 /* we are working on non-current tsk/mm */

SEC("iter.s/task")
int dump_task_sleepable(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	static const char info[] = "    === END ===";
	struct pt_regs *regs;
	void *ptr;
	uint32_t user_data = 0;
	int numread;

	if (task == (void *)0) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	regs = (struct pt_regs *)bpf_task_pt_regs(task);
	if (regs == (void *)0) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}
	ptr = (void *)PT_REGS_IP(regs);

	// Try to read the contents of the task's instruction pointer from the
	// remote task's address space.
	numread = bpf_access_process_vm(task,
					(unsigned long)ptr,
					(void *)&user_data,
					sizeof(uint32_t),
					FOLL_REMOTE);
	if (numread != sizeof(uint32_t)) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "    tgid      gid     data\n");

	BPF_SEQ_PRINTF(seq, "%8d %8d %8d\n", task->tgid, task->pid, user_data);
	return 0;
}
