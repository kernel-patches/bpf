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

int pid;
u64 err;

static int cpumask_iter(struct bpf_iter_meta *meta, struct cgroup *cgrp, u32 nr_cpus)
{
	struct task_struct *p;
	u32 nr_running = 0;
	struct rq *rq;
	u64 cpus = 0;
	int *cpu, ret;

	/* epilogue */
	if (!cgrp)
		return 0;

	p = bpf_task_from_pid(pid);
	if (!p)
		return 1;

	ret = bpf_probe_read_kernel_common(&cpus, 8, p->cpus_ptr);
	if (ret) {
		err = 95;
		goto out;
	}
	bpf_for_each(bits, cpu, p->cpus_ptr, nr_cpus) {
		rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, *cpu);
		/* Every valid CPU should possess a runqueue, even in the event of being offline */
		if (!rq)
			break;
		nr_running += rq->nr_running;
	}
	if (nr_running == 0)
		err = cpus;

out:
	bpf_task_release(p);
	return 0;
}

SEC("iter.s/cgroup")
int BPF_PROG(cpumask_memalloc, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	return cpumask_iter(meta, cgrp, 128);
}

SEC("iter.s/cgroup")
int BPF_PROG(cpumask_copy, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	return cpumask_iter(meta, cgrp, 16);
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

	/* The max number of memalloc is 4096, thus it will fail to allocate (8192 * 8) */
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

	/* It functions properly without invoking bpf_iter_bits_next(). */

	bpf_iter_bits_destroy(&it);
	bpf_task_release(p);
	return 0;
}
