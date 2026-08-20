// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "cgroup_iter_cpu.h"

char _license[] SEC("license") = "GPL";

struct cpu_query cpu_query SEC(".data.query");

extern const void __cpu_possible_mask __ksym;

struct cgroup_base_stat___local {
	struct task_cputime cputime;
	__u64 forceidle_sum;
	__u64 ntime;
} __attribute__((preserve_access_index));

static __always_inline __u64 read_throttled_self(struct task_group *tg, __u32 cpu)
{
	struct cfs_rq *cfs_rq;

	cfs_rq = bpf_per_cpu_ptr(tg->cfs_rq, cpu);
	if (!cfs_rq)
		return 0;

	return BPF_CORE_READ(cfs_rq, throttled_clock_self_time);
}

SEC("iter.s/cgroup")
int cgroup_cpu_query(struct bpf_iter__cgroup *ctx)
{
	struct cgroup_base_stat___local bstat = {};
	struct cgroup *cgrp = ctx->cgroup;
	struct cgroup_subsys_state *css;
	struct task_group *tg;
	__u64 throttled_self = 0;
	int ssid;

	if (!cgrp)
		return 1;

	css_rstat_flush(&cgrp->self);
	bpf_cgroup_base_stat(cgrp, (struct cgroup_base_stat *)&bstat);

	cpu_query.usage_usec = bstat.cputime.sum_exec_runtime / 1000;
	cpu_query.user_usec = bstat.cputime.utime / 1000;
	cpu_query.system_usec = bstat.cputime.stime / 1000;
	cpu_query.nice_usec = bstat.ntime / 1000;
	cpu_query.forceidle_usec = 0;
	if (bpf_core_field_exists(bstat.forceidle_sum))
		cpu_query.forceidle_usec = bstat.forceidle_sum / 1000;

	bpf_rcu_read_lock();
	if (!bpf_core_enum_value_exists(enum cgroup_subsys_id, cpu_cgrp_id) ||
	    !bpf_ksym_exists(bpf_css_to_task_group))
		goto unlock;

	ssid = bpf_core_enum_value(enum cgroup_subsys_id, cpu_cgrp_id);
	css = cgrp->subsys[ssid];
	if (!css)
		goto unlock;

	tg = bpf_css_to_task_group(css);
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

	if (tg && bpf_core_field_exists(tg->cfs_rq) &&
	    bpf_core_field_exists(struct cfs_rq, throttled_clock_self_time)) {
		__u32 mask_bytes = bpf_core_type_size(struct cpumask);
		__u32 full_words = mask_bytes / sizeof(__u64);
		int *cpu;

		if (full_words)
			bpf_for_each(bits, cpu,
				     (const __u64 *)&__cpu_possible_mask,
				     full_words)
				throttled_self += read_throttled_self(tg, *cpu);

		if (mask_bytes & (sizeof(__u64) - 1)) {
			__u32 tail = 0;
			const void *src = (const char *)&__cpu_possible_mask +
					  full_words * sizeof(__u64);
			int bit;

			if (!bpf_probe_read_kernel(&tail, sizeof(tail), src))
				bpf_for(bit, 0, 32)
					if (tail & (1U << bit)) {
						__u32 tail_cpu = full_words * 64 + bit;

						throttled_self +=
							read_throttled_self(tg, tail_cpu);
					}
		}
	}

unlock:
	bpf_rcu_read_unlock();
	cpu_query.throttled_self_usec = throttled_self / 1000;

	return 0;
}
