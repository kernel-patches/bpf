// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"
#include "task_kfunc_common.h"
#include "cpumask_common.h"

char _license[] SEC("license") = "GPL";

SEC("iter.s/cgroup")
__failure __msg("R2 must be a rcu pointer")
int BPF_PROG(test_cpumask_iter_no_rcu, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct task_struct *p;
	int *cpu;

	p = bpf_task_from_pid(1);
	if (!p)
		return 1;

	bpf_for_each(cpumask, cpu, p->cpus_ptr) {
	}
	bpf_task_release(p);
	return 0;
}

SEC("iter/cgroup")
__failure __msg("Possibly NULL pointer passed to trusted arg1")
int BPF_PROG(test_cpumask_iter_null_pointer, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct cpumask *mask = NULL;
	int *cpu;

	bpf_for_each(cpumask, cpu, mask) {
	}
	return 0;
}

SEC("iter.s/cgroup")
__failure __msg("Unreleased reference id=3 alloc_insn=10")
int BPF_PROG(test_cpumask_iter_no_destroy, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_cpumask it;
	struct task_struct *p;

	p = bpf_task_from_pid(1);
	if (!p)
		return 1;

	bpf_rcu_read_lock();
	bpf_iter_cpumask_new(&it, p->cpus_ptr);
	bpf_rcu_read_unlock();

	bpf_iter_cpumask_next(&it);
	bpf_task_release(p);
	return 0;
}

SEC("iter/cgroup")
__failure __msg("expected an initialized iter_cpumask as arg #1")
int BPF_PROG(test_cpumask_iter_next_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_cpumask *it = NULL;

	bpf_iter_cpumask_next(it);
	return 0;
}

SEC("iter/cgroup")
__failure __msg("expected an initialized iter_cpumask as arg #1")
int BPF_PROG(test_cpumask_iter_next_uninit2, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_cpumask it = {};

	bpf_iter_cpumask_next(&it);
	return 0;
}

SEC("iter/cgroup")
__failure __msg("expected an initialized iter_cpumask as arg #1")
int BPF_PROG(test_cpumask_iter_destroy_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_cpumask_kern it = {.cpu = -1};
	struct bpf_cpumask *mask;

	mask = bpf_cpumask_create();
	if (!mask)
		return 1;

	bpf_cpumask_setall(mask);
	it.mask = &mask->cpumask;
	bpf_iter_cpumask_destroy((struct bpf_iter_cpumask *)&it);
	bpf_cpumask_release(mask);
	return 0;
}
