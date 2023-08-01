// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Yafang Shao <laoar.shao@gmail.com> */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define __percpu __attribute__((btf_type_tag("percpu")))

enum bpf_cpu_mask_type cpu_mask;
__u32 pid;

struct callback_ctx {
	__u32 nr_running;
	__u32 id;
};

static uint64_t cgroup_id(struct cgroup *cgrp)
{
	return cgrp->kn->id;
}

static int callback(__u32 cpu, void *ctx, const void *ptr)
{
	unsigned int tasks[NR_PSI_TASK_COUNTS];
	const struct psi_group_cpu *groupc = ptr;
	struct callback_ctx *data = ctx;

	bpf_probe_read_kernel(&tasks, sizeof(tasks), &groupc->tasks);
	data->nr_running += tasks[NR_RUNNING];
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(psi_cgroup, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct seq_file *seq = (struct seq_file *)meta->seq;
	struct psi_group_cpu __percpu *pcpu_ptr;
	struct callback_ctx data;
	struct psi_group *psi;
	__u64 cg_id;
	int ret;

	cg_id = cgrp ? cgroup_id(cgrp) : 0;
	if (!cg_id)
		return 1;

	psi = cgrp->psi;
	if (!psi)
		return 1;

	pcpu_ptr = psi->pcpu;
	if (!pcpu_ptr)
		return 1;

	data.nr_running = 0;
	data.id = cg_id;
	ret = bpf_for_each_cpu(callback, &data, pcpu_ptr, cpu_mask, pid);
	BPF_SEQ_PRINTF(seq, "nr_running %d ret %d\n", data.nr_running, ret);

	return ret ? 1 : 0;
}

char _license[] SEC("license") = "GPL";
