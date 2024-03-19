// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Netflix, Inc.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct cgroup *bpf_task_get_cgroup(struct task_struct *task) __ksym;
void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

int pid = 0;
u64 cgroup_id = 0;

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	struct cgroup *cgrp;

	if (prev->pid != pid)
		return 0;

	cgrp = bpf_task_get_cgroup(prev);
	if (cgrp == NULL)
		return 0;
	cgroup_id = cgrp->kn->id;

	bpf_cgroup_release(cgrp);
	return 0;
}

char _license[] SEC("license") = "GPL";
