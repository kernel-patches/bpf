/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_NUMA_BALANCING_H
#define _LINUX_SCHED_NUMA_BALANCING_H

/*
 * This is the interface between the scheduler and the MM that
 * implements memory access pattern based NUMA-balancing:
 */

#include <linux/bpf_numab.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>

#define TNF_MIGRATED	0x01
#define TNF_NO_GROUP	0x02
#define TNF_SHARED	0x04
#define TNF_FAULT_LOCAL	0x08
#define TNF_MIGRATE_FAIL 0x10

enum numa_vmaskip_reason {
	NUMAB_SKIP_UNSUITABLE,
	NUMAB_SKIP_SHARED_RO,
	NUMAB_SKIP_INACCESSIBLE,
	NUMAB_SKIP_SCAN_DELAY,
	NUMAB_SKIP_PID_INACTIVE,
	NUMAB_SKIP_IGNORE_PID,
	NUMAB_SKIP_SEQ_COMPLETED,
};

#ifdef CONFIG_NUMA_BALANCING
extern void task_numa_fault(int last_node, int node, int pages, int flags);
extern pid_t task_numa_group_id(struct task_struct *p);
extern void set_numabalancing_state(bool enabled);
extern void task_numa_free(struct task_struct *p, bool final);
bool should_numa_migrate_memory(struct task_struct *p, struct folio *folio,
				int src_nid, int dst_cpu);

extern struct static_key_false sched_numa_balancing;

/* Whether NUMA balancing applies to @p: the global sysctl state, possibly
 * overridden by a BPF policy attached to @p's cgroup. The requests of
 * the task's cgroup and of every ancestor are combined; a policy can
 * always opt out, so a latency-sensitive workload is never forced in.
 */
static inline bool task_numab_enabled(struct task_struct *p)
{
	u32 state = bpf_numab_mode(p, NULL);

	/* A policy can always opt out, regardless of the global state. */
	if (state & BPF_NUMAB_DISABLED)
		return false;
	if (state & (BPF_NUMAB_NORMAL | BPF_NUMAB_TIERING))
		return true;
	return static_branch_unlikely(&sched_numa_balancing);
}

static inline bool numab_mode_tiering(void)
{
	if (sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING)
		return true;
	return false;
}

/*
 * Whether @p runs in tiering mode, i.e. whether faults on non-top-tier
 * memory still feed its NUMA statistics. The requests of the task's
 * cgroup and of every ancestor are combined; DISABLED and NORMAL both
 * opt out of tiering (a policy can always opt out), so only an
 * unopposed TIERING request engages it. Without any request, the
 * global sysctl decides.
 */
static inline bool task_numab_mode_tiering(struct task_struct *p)
{
	u32 state = bpf_numab_mode(p, NULL);

	if (state & (BPF_NUMAB_DISABLED | BPF_NUMAB_NORMAL))
		return false;
	if (state & BPF_NUMAB_TIERING)
		return true;
	return numab_mode_tiering();
}

/*
 * Whether @folio's memory participates in tiering, i.e. whether its
 * _last_cpupid carries an access time instead of a cpupid. The requests
 * of the owner cgroup and of every ancestor are combined. DISABLED
 * never speaks for memory (it is a task-surface request), so only
 * NORMAL and TIERING are consulted here; without either, the global
 * sysctl decides.
 */
static inline bool folio_numab_mode_tiering(struct folio *folio)
{
	u32 state = bpf_numab_mode(NULL, folio);

	if (state & BPF_NUMAB_NORMAL)
		return false;
	if (state & BPF_NUMAB_TIERING)
		return true;
	return numab_mode_tiering();
}
#else
static inline void task_numa_fault(int last_node, int node, int pages,
				   int flags)
{
}
static inline pid_t task_numa_group_id(struct task_struct *p)
{
	return 0;
}
static inline void set_numabalancing_state(bool enabled)
{
}
static inline void task_numa_free(struct task_struct *p, bool final)
{
}
static inline bool should_numa_migrate_memory(struct task_struct *p,
				struct folio *folio, int src_nid, int dst_cpu)
{
	return true;
}
static inline bool task_numab_enabled(struct task_struct *p)
{
	return false;
}
static inline bool numab_mode_tiering(void)
{
	return false;
}
static inline bool task_numab_mode_tiering(struct task_struct *p)
{
	return false;
}
static inline bool folio_numab_mode_tiering(struct folio *folio)
{
	return false;
}
#endif

#endif /* _LINUX_SCHED_NUMA_BALANCING_H */
