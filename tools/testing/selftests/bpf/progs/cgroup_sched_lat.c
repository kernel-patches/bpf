// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define TASK_RUNNING 0
#define BPF_F_CURRENT_CPU 0xffffffffULL

extern void fair_sched_class __ksym;
extern bool CONFIG_FAIR_GROUP_SCHED __kconfig;
extern bool CONFIG_CGROUP_SCHED __kconfig;

struct wait_lat {
	/* Queue_self stands for the latency a task experiences while waiting
	 * behind the tasks that are from the same cgroup.
	 *
	 * Queue_other stands for the latency a task experiences while waiting
	 * behind the tasks that are from other cgroups.
	 *
	 * For example, if there are three tasks: A, B and C. Suppose A and B
	 * are in the same cgroup and C is in another cgroup and we see A has
	 * a queueing latency X milliseconds. Let's say during the X milliseconds,
	 * B has run for Y milliseconds. We can break down X to two parts: time
	 * when B is on cpu, that is Y; the time when C is on cpu, that is X - Y.
	 *
	 * Queue_self is the former (Y) while queue_other is the latter (X - Y).
	 *
	 * large value in queue_self is an indication of contention within a
	 * cgroup; while large value in queue_other is an indication of
	 * contention from multiple cgroups.
	 */
	u64 queue_self;
	u64 queue_other;
};

struct timestamp {
	/* timestamp when last queued */
	u64 tsp;

	/* cgroup exec_clock when last queued */
	u64 exec_clock;
};

/* Map to store per-cgroup wait latency */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct wait_lat);
	__uint(max_entries, 65532);
} cgroup_lat SEC(".maps");

/* Map to store per-task queue timestamp */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct timestamp);
} start SEC(".maps");

/* adapt from task_cfs_rq in kernel/sched/sched.h */
__always_inline
struct cfs_rq *task_cfs_rq(struct task_struct *t)
{
	if (!CONFIG_FAIR_GROUP_SCHED)
		return NULL;

	return BPF_CORE_READ(&t->se, cfs_rq);
}

/* record enqueue timestamp */
__always_inline
static int trace_enqueue(struct task_struct *t)
{
	u32 pid = t->pid;
	struct timestamp *ptr;
	struct cfs_rq *cfs_rq;

	if (!pid)
		return 0;

	/* only measure for CFS tasks */
	if (t->sched_class != &fair_sched_class)
		return 0;

	ptr = bpf_task_storage_get(&start, t, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	/* CONFIG_FAIR_GROUP_SCHED may not be enabled */
	cfs_rq = task_cfs_rq(t);
	if (!cfs_rq)
		return 0;

	ptr->tsp = bpf_ktime_get_ns();
	ptr->exec_clock = BPF_CORE_READ(cfs_rq, exec_clock);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (void *)ctx[0];

	return trace_enqueue(p);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (void *)ctx[0];

	return trace_enqueue(p);
}

/* task_group() from kernel/sched/sched.h */
__always_inline
struct task_group *task_group(struct task_struct *p)
{
	if (!CONFIG_CGROUP_SCHED)
		return NULL;

	return BPF_CORE_READ(p, sched_task_group);
}

__always_inline
struct cgroup *task_cgroup(struct task_struct *p)
{
	struct task_group *tg;

	tg = task_group(p);
	if (!tg)
		return NULL;

	return BPF_CORE_READ(tg, css).cgroup;
}

__always_inline
u64 max(u64 x, u64 y)
{
	return x > y ? x : y;
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	/* TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	u64 delta, delta_self, delta_other, id;
	struct cfs_rq *cfs_rq;
	struct timestamp *tsp;
	struct wait_lat *lat;
	struct cgroup *cgroup;

	/* ivcsw: treat like an enqueue event and store timestamp */
	if (prev->__state == TASK_RUNNING)
		trace_enqueue(prev);

	/* only measure for CFS tasks */
	if (next->sched_class != &fair_sched_class)
		return 0;

	/* fetch timestamp and calculate delta */
	tsp = bpf_task_storage_get(&start, next, 0, 0);
	if (!tsp)
		return 0;   /* missed enqueue */

	/* CONFIG_FAIR_GROUP_SCHED may not be enabled */
	cfs_rq = task_cfs_rq(next);
	if (!cfs_rq)
		return 0;

	/* cpu controller may not be enabled */
	cgroup = task_cgroup(next);
	if (!cgroup)
		return 0;

	/* calculate self delay and other delay */
	delta = bpf_ktime_get_ns() - tsp->tsp;
	delta_self = BPF_CORE_READ(cfs_rq, exec_clock) - tsp->exec_clock;
	if (delta_self > delta)
		delta_self = delta;
	delta_other = delta - delta_self;

	/* insert into cgroup_lat map */
	id = BPF_CORE_READ(cgroup, kn, id);
	lat = bpf_map_lookup_elem(&cgroup_lat, &id);
	if (!lat) {
		struct wait_lat w = {
			.queue_self = delta_self,
			.queue_other = delta_other,
		};

		bpf_map_update_elem(&cgroup_lat, &id, &w, BPF_ANY);
	} else {
		lat->queue_self = max(delta_self, lat->queue_self);
		lat->queue_other = max(delta_other, lat->queue_other);
	}

	bpf_task_storage_delete(&start, next);
	return 0;
}

SEC("iter/cgroup")
int dump_cgroup(struct bpf_iter__cgroup *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct cgroup *cgroup = ctx->cgroup;
	struct wait_lat *lat;
	u64 id = cgroup->kn->id;

	BPF_SEQ_PRINTF(seq, "cgroup_id: %8lu\n", id);
	lat = bpf_map_lookup_elem(&cgroup_lat, &id);
	if (lat) {
		BPF_SEQ_PRINTF(seq, "queue_self: %8lu\n", lat->queue_self);
		BPF_SEQ_PRINTF(seq, "queue_other: %8lu\n", lat->queue_other);
	} else {
		/* print anyway for universal parsing logic in userspace. */
		BPF_SEQ_PRINTF(seq, "queue_self: %8d\n", 0);
		BPF_SEQ_PRINTF(seq, "queue_other: %8d\n", 0);
	}
	return 0;
}
