// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "task_kfunc_common.h"
#include "cpumask_common.h"

char _license[] SEC("license") = "GPL";

extern const struct psi_group_cpu system_group_pcpu __ksym __weak;
extern const struct rq runqueues __ksym __weak;

int pid;

#define READ_PERCPU_DATA(meta, cgrp, mask)							\
{												\
	u32 nr_running = 0, psi_nr_running = 0, nr_cpus = 0;					\
	struct psi_group_cpu *groupc;								\
	struct rq *rq;										\
	int *cpu;										\
												\
	bpf_for_each(cpumask, cpu, mask) {							\
		rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, *cpu);				\
		if (!rq) {									\
			err += 1;								\
			continue;								\
		}										\
		nr_running += rq->nr_running;							\
		nr_cpus += 1;									\
												\
		groupc = (struct psi_group_cpu *)bpf_per_cpu_ptr(&system_group_pcpu, *cpu);	\
		if (!groupc) {									\
			err += 1;								\
			continue;								\
		}										\
		psi_nr_running += groupc->tasks[NR_RUNNING];					\
	}											\
	BPF_SEQ_PRINTF(meta->seq, "nr_running %u nr_cpus %u psi_running %u\n",			\
		       nr_running, nr_cpus, psi_nr_running);					\
}

SEC("iter.s/cgroup")
int BPF_PROG(test_cpumask_iter_sleepable, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct task_struct *p;

	/* epilogue */
	if (!cgrp)
		return 0;

	bpf_rcu_read_lock();
	p = bpf_task_from_pid(pid);
	if (!p) {
		bpf_rcu_read_unlock();
		return 1;
	}

	READ_PERCPU_DATA(meta, cgrp, p->cpus_ptr);
	bpf_task_release(p);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("iter/cgroup")
int BPF_PROG(test_cpumask_iter, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct task_struct *p;

	/* epilogue */
	if (!cgrp)
		return 0;

	p = bpf_task_from_pid(pid);
	if (!p)
		return 1;

	READ_PERCPU_DATA(meta, cgrp, p->cpus_ptr);
	bpf_task_release(p);
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(test_cpumask_iter_next_no_rcu, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_cpumask it;
	struct task_struct *p;

	p = bpf_task_from_pid(1);
	if (!p)
		return 1;

	/* RCU is only required by bpf_iter_cpumask_new(). */
	bpf_rcu_read_lock();
	bpf_iter_cpumask_new(&it, p->cpus_ptr);
	bpf_rcu_read_unlock();

	bpf_iter_cpumask_next(&it);
	bpf_iter_cpumask_destroy(&it);

	bpf_task_release(p);
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(test_cpumask_iter_no_next, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_cpumask it;
	struct task_struct *p;

	p = bpf_task_from_pid(1);
	if (!p)
		return 1;

	bpf_rcu_read_lock();
	bpf_iter_cpumask_new(&it, p->cpus_ptr);
	bpf_rcu_read_unlock();

	/* It is fine without calling bpf_iter_cpumask_next(). */

	bpf_iter_cpumask_destroy(&it);
	bpf_task_release(p);
	return 0;
}
