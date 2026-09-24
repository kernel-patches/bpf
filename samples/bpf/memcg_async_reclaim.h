/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared between memcg_async_reclaim.bpf.c and memcg_async_reclaim_user.c.
 *
 * Both sides must have pulled in their type headers first: vmlinux.h for the
 * BPF program, <linux/types.h> (via test_progs.h or libbpf) for the loader.
 */
#ifndef __MEMCG_ASYNC_RECLAIM_H
#define __MEMCG_ASYNC_RECLAIM_H

struct reclaim_cfg {
	/* Cgroup whose refaults are watched, i.e. the one under pressure. */
	__u64 monitor_cgroup_id;
	/* Cgroup that gets reclaimed from when the monitor refaults. */
	__u64 target_cgroup_id;
	/* Refault delta per tick that starts a reclaim round. */
	__u64 refault_threshold;
	/* Monitor tick period, in nanoseconds. */
	__u64 interval_ns;
	/* Bytes requested per bpf_wq callback. */
	__u64 batch_bytes;
	/* Callbacks per reclaim round. */
	__u64 max_batches;
	/* Passed through to bpf_proactive_reclaim(): -1, 0..200, or 201. */
	__s64 swappiness;
};

/* Outcome of a single reclaim attempt, reported through the ringbuf. */
enum reclaim_outcome {
	RECLAIM_OUTCOME_CALLED,
	RECLAIM_OUTCOME_SKIPPED_DYING,
	RECLAIM_OUTCOME_TARGET_GONE,
};

struct reclaim_event {
	__u64 outcome;
};

#endif /* __MEMCG_ASYNC_RECLAIM_H */
