// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "task_kfunc_common.h"
#include "cpumask_common.h"

extern const struct psi_group_cpu system_group_pcpu __ksym __weak;
extern const struct rq runqueues __ksym __weak;

int target_pid;

SEC("iter.s/cgroup")
int BPF_PROG(cpu_cgroup, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	u32 nr_running = 0, psi_nr_running = 0, nr_cpus = 0;
	struct psi_group_cpu *groupc;
	struct task_struct *p;
	struct rq *rq;
	int *cpu;

	/* epilogue */
	if (cgrp == NULL)
		return 0;

	bpf_rcu_read_lock();
	p = bpf_task_from_pid(target_pid);
	if (!p) {
		bpf_rcu_read_unlock();
		return 1;
	}

	bpf_for_each(cpumask, cpu, p->cpus_ptr) {
		rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, *cpu);
		if (!rq)
			continue;
		nr_running += rq->nr_running;
		nr_cpus += 1;

		groupc = (struct psi_group_cpu *)bpf_per_cpu_ptr(&system_group_pcpu, *cpu);
		if (!groupc)
			continue;
		psi_nr_running += groupc->tasks[NR_RUNNING];
	}
	BPF_SEQ_PRINTF(meta->seq, "nr_running %u nr_cpus %u psi_running %u\n",
		       nr_running, nr_cpus, psi_nr_running);

	bpf_task_release(p);
	bpf_rcu_read_unlock();
	return 0;
}

char _license[] SEC("license") = "GPL";
