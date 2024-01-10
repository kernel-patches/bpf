// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "task_kfunc_common.h"
#include "cpumask_common.h"

extern const struct psi_group_cpu system_group_pcpu __ksym __weak;
extern const struct rq runqueues __ksym __weak;

int target_pid;

SEC("iter/cgroup")
int BPF_PROG(cpu_cgroup, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	u32 *cpu, nr_running = 0, psi_nr_running = 0, nr_cpus = 0;
	unsigned int tasks[NR_PSI_TASK_COUNTS];
	struct psi_group_cpu *groupc;
	struct bpf_cpumask *mask;
	struct task_struct *p;
	struct rq *rq;

	/* epilogue */
	if (cgrp == NULL)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return 1;

	p = bpf_task_from_pid(target_pid);
	if (!p) {
		bpf_cpumask_release(mask);
		return 1;
	}

	bpf_cpumask_copy(mask, p->cpus_ptr);
	bpf_for_each(cpumask, cpu, &mask->cpumask) {
		rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, *cpu);
		if (!rq)
			continue;
		nr_running += rq->nr_running;
		nr_cpus += 1;

		groupc = (struct psi_group_cpu *)bpf_per_cpu_ptr(&system_group_pcpu, *cpu);
		if (!groupc)
			continue;
		bpf_probe_read_kernel(&tasks, sizeof(tasks), &groupc->tasks);
		psi_nr_running += tasks[NR_RUNNING];
	}
	BPF_SEQ_PRINTF(meta->seq, "nr_running %u nr_cpus %u psi_running %u\n",
		       nr_running, nr_cpus, psi_nr_running);

	bpf_task_release(p);
	bpf_cpumask_release(mask);
	return 0;
}

char _license[] SEC("license") = "GPL";
