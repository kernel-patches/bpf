// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("iter/cgroup_task")
int cgroup_task_cnt(struct bpf_iter__cgroup_task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	static __u32 nr_total;

	if (!task) {
		BPF_SEQ_PRINTF(seq, "nr_total %u\n", nr_total);
		return 0;
	}

	if (ctx->meta->seq_num == 0)
		nr_total = 0;
	nr_total++;
	return 0;
}

SEC("iter/cgroup_task")
int cgroup_task_pid(struct bpf_iter__cgroup_task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (!task)
		return 0;

	BPF_SEQ_PRINTF(seq, "pid %u\n", task->pid);
	return 0;
}
