// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <linux/const.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

extern const struct rq runqueues __ksym __weak;

int bpf_iter_bits_new(struct bpf_iter_bits *it, const void *unsafe_ptr__ign,
		      u32 nr_bits) __ksym __weak;
int *bpf_iter_bits_next(struct bpf_iter_bits *it) __ksym __weak;
void bpf_iter_bits_destroy(struct bpf_iter_bits *it) __ksym __weak;

int pid, err;

SEC("iter.s/cgroup")
int BPF_PROG(cpumask_iter, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	u32 nr_running = 0, nr_cpus = 0;
	struct task_struct *p;
	struct rq *rq;
	int *cpu;

	/* epilogue */
	if (!cgrp)
		return 0;

	p = bpf_task_from_pid(pid);
	if (!p)
		return 1;

	bpf_for_each(bits, cpu, p->cpus_ptr, 8192) {
		rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, *cpu);
		/* Each valid CPU must have a runqueue, even if it is offline. */
		if (!rq)
			break;

		nr_running += rq->nr_running;
		nr_cpus++;
	}
	BPF_SEQ_PRINTF(meta->seq, "nr_running %u nr_cpus %u\n",
		       nr_running, nr_cpus);
	bpf_task_release(p);
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(null_pointer, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	int *cpu;

	bpf_for_each(bits, cpu, NULL, 8192)
		err++;
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(zero_bit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct task_struct *p;
	int *cpu;

	p = bpf_task_from_pid(pid);
	if (!p)
		return 1;

	bpf_for_each(bits, cpu, p->cpus_ptr, 0)
		err++;
	bpf_task_release(p);
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(no_mem, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct task_struct *p;
	int *cpu;

	p = bpf_task_from_pid(pid);
	if (!p)
		return 1;

	/* The max size of memalloc is 4096, so it will fail to allocate (8192 * 8) */
	bpf_for_each(bits, cpu, p->cpus_ptr, 8192 * 8)
		err++;
	bpf_task_release(p);
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(no_next, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_bits it;
	struct task_struct *p;

	p = bpf_task_from_pid(1);
	if (!p)
		return 1;

	bpf_iter_bits_new(&it, p->cpus_ptr, 8192);

	/* It is fine without calling bpf_iter_bits_next(). */

	bpf_iter_bits_destroy(&it);
	bpf_task_release(p);
	return 0;
}
