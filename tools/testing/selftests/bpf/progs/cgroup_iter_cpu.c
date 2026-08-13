// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "cgroup_iter_cpu.h"

char _license[] SEC("license") = "GPL";

struct cpu_query cpu_query SEC(".data.query");

SEC("iter.s/cgroup")
int cgroup_cpu_query(struct bpf_iter__cgroup *ctx)
{
	struct cpu_cgroup_cputime ct = {};
	struct cgroup *cgrp = ctx->cgroup;
	struct cgroup_subsys_state *css;
	struct task_group *tg;

	if (!cgrp)
		return 1;

	bpf_cpu_cgroup_flush_stats(cgrp);
	bpf_cpu_cgroup_cputime(cgrp, &ct);

	cpu_query.usage_usec = ct.usage_usec;
	cpu_query.user_usec = ct.user_usec;
	cpu_query.system_usec = ct.system_usec;
	cpu_query.nice_usec = ct.nice_usec;
	cpu_query.forceidle_usec = ct.forceidle_usec;

	bpf_rcu_read_lock();
	css = cgrp->subsys[cpu_cgrp_id];
	tg = (struct task_group *)css;
	if (tg && bpf_core_field_exists(tg->cfs_bandwidth.nr_periods)) {
		cpu_query.nr_periods =
			(__u32)BPF_CORE_READ(tg, cfs_bandwidth.nr_periods);
		cpu_query.nr_throttled =
			(__u32)BPF_CORE_READ(tg, cfs_bandwidth.nr_throttled);
		cpu_query.throttled_usec =
			BPF_CORE_READ(tg, cfs_bandwidth.throttled_time) / 1000;
		cpu_query.nr_bursts =
			(__u32)BPF_CORE_READ(tg, cfs_bandwidth.nr_burst);
		cpu_query.burst_usec =
			BPF_CORE_READ(tg, cfs_bandwidth.burst_time) / 1000;
	}
	bpf_rcu_read_unlock();

	/* a sum over every possible cpu, so the test uses a kfunc */
	cpu_query.throttled_self_usec = bpf_cpu_cgroup_throttled_self(cgrp);

	return 0;
}
