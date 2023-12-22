// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cpumask_common.h"

extern const struct rq runqueues __ksym __weak;

int target_pid;

SEC("iter/cgroup")
int BPF_PROG(cpu_cgroup, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	u32 *cpu, nr_running = 0, nr_cpus = 0;
	struct bpf_cpumask *mask;
	struct rq *rq;
	int ret;

	/* epilogue */
	if (cgrp == NULL)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return 1;

	ret = bpf_cpumask_set_from_pid(&mask->cpumask, target_pid);
	if (ret == false) {
		bpf_cpumask_release(mask);
		return 1;
	}

	bpf_for_each(cpumask, cpu, &mask->cpumask) {
		rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, *cpu);
		if (!rq)
			continue;

		nr_running += rq->nr_running;
		nr_cpus += 1;
	}
	BPF_SEQ_PRINTF(meta->seq, "nr_running %u nr_cpus %u\n", nr_running, nr_cpus);

	bpf_cpumask_release(mask);
	return 0;
}

char _license[] SEC("license") = "GPL";
