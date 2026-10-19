/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_NUMA_BALANCING_H
#define _LINUX_SCHED_NUMA_BALANCING_H

/*
 * This is the interface between the scheduler and the MM that
 * implements memory access pattern based NUMA-balancing:
 */

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

#ifdef CONFIG_BPF_NUMAB
/*
 * A cgroup can override the global NUMA balancing state for the tasks it
 * runs and the memory it owns: the bpf_numab_set_mode() kfunc stores a
 * requested mode in struct cgroup, and the readers below combine the
 * requests of the matching cgroup and of every ancestor.
 * numab_cgroup_mode_set stays off while no cgroup makes a request, so
 * the consult costs the hot paths nothing until then.
 */
extern struct static_key_false numab_cgroup_mode_set;

/* The per-cgroup request domain: this, or a NUMA_BALANCING_* bitmask. */
#define NUMAB_FOLLOW_SYSTEM (-1)

/*
 * The combined request for the chain of @p's cgroup:
 * NUMA_BALANCING_DISABLED when any cgroup in the chain opts out, the OR
 * of the requested bits otherwise, NUMAB_FOLLOW_SYSTEM when no cgroup
 * makes a request.
 */
int task_numab_mode(struct task_struct *p);

/*
 * The combined request for the chain of the memcg @folio is charged to.
 * An opt-out never speaks for memory, so it is not part of the answer;
 * an uncharged folio makes no request.
 */
int folio_numab_mode(struct folio *folio);
#endif

/*
 * Whether NUMA balancing applies to @p: the global sysctl state, possibly
 * overridden by the requests of @p's cgroup and of every ancestor.
 * A cgroup's request always takes priority over the system setting.
 */
static inline bool task_numab_enabled(struct task_struct *p)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = task_numab_mode(p);

		if (mode != NUMAB_FOLLOW_SYSTEM)
			return mode != NUMA_BALANCING_DISABLED;
	}
#endif
	return static_branch_likely(&sched_numa_balancing);
}

/* Whether NUMA balancing is in memory tiering mode. */
static inline bool numab_in_tiering_mode(void)
{
	return sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING;
}

/* Whether NUMA balancing is in normal mode. */
static inline bool numab_in_normal_mode(void)
{
	return sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL;
}

/*
 * Whether @p runs in tiering mode, i.e. whether faults on non-top-tier
 * memory still feed its NUMA statistics. The requests of the task's
 * cgroup and of every ancestor are combined; an opt-out wins, otherwise
 * the bits are read independently, as the sysctl reads them. Without
 * any request, the global sysctl decides.
 */
static inline bool task_numab_in_tiering_mode(struct task_struct *p)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = task_numab_mode(p);

		if (mode != NUMAB_FOLLOW_SYSTEM)
			return mode & NUMA_BALANCING_MEMORY_TIERING;
	}
#endif
	return numab_in_tiering_mode();
}

/*
 * Whether @folio's memory participates in tiering, i.e. whether its
 * _last_cpupid carries an access time instead of a cpupid. The
 * requests of the owner cgroup and of every ancestor are combined.
 * DISABLED never speaks for memory (it is a task-side request), so only
 * NORMAL and TIERING are consulted here; without either, the global
 * sysctl decides.
 */
static inline bool folio_numab_in_tiering_mode(struct folio *folio)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = folio_numab_mode(folio);

		if (mode != NUMAB_FOLLOW_SYSTEM)
			return mode & NUMA_BALANCING_MEMORY_TIERING;
	}
#endif
	return numab_in_tiering_mode();
}

/*
 * Whether @folio's owner asks for the normal mode, i.e. whether hinting
 * faults on its top-tier pages should still feed the scheduler's
 * placement statistics. The requests of the owner cgroup and of every
 * ancestor are combined; without any request, the global sysctl
 * decides. This is deliberately independent of tiering participation:
 * a folio can record access times and still keep its top-tier scanning.
 */
static inline bool folio_numab_in_normal_mode(struct folio *folio)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = folio_numab_mode(folio);

		if (mode != NUMAB_FOLLOW_SYSTEM)
			return mode & NUMA_BALANCING_NORMAL;
	}
#endif
	return numab_in_normal_mode();
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
static inline bool numab_in_tiering_mode(void)
{
	return false;
}
static inline bool numab_in_normal_mode(void)
{
	return false;
}
static inline bool task_numab_in_tiering_mode(struct task_struct *p)
{
	return false;
}
static inline bool folio_numab_in_tiering_mode(struct folio *folio)
{
	return false;
}
static inline bool folio_numab_in_normal_mode(struct folio *folio)
{
	return false;
}
#endif

#endif /* _LINUX_SCHED_NUMA_BALANCING_H */
