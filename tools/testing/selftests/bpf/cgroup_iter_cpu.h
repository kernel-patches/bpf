/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#ifndef __CGROUP_ITER_CPU_H
#define __CGROUP_ITER_CPU_H

struct cpu_query {
	/* base cpu time, from cpu.stat */
	__u64 usage_usec;
	__u64 user_usec;
	__u64 system_usec;
	__u64 nice_usec;
	__u64 forceidle_usec;
	/* CFS bandwidth throttling, from cpu.stat and cpu.stat.local */
	__u64 nr_periods;
	__u64 nr_throttled;
	__u64 throttled_usec;
	__u64 nr_bursts;
	__u64 burst_usec;
	__u64 throttled_self_usec;
};

#endif /* __CGROUP_ITER_CPU_H */
