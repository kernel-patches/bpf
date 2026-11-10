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

/*
 * Mode values used by the NUMA balancing helpers.
 */
enum numab_mode {
	NUMAB_FOLLOW_SYSTEM	= -1,
	NUMAB_DISABLED		= NUMA_BALANCING_DISABLED,
	NUMAB_NORMAL		= NUMA_BALANCING_NORMAL,
	NUMAB_TIERING		= NUMA_BALANCING_MEMORY_TIERING,
	NUMAB_NORMAL_TIERING	= NUMA_BALANCING_NORMAL |
				  NUMA_BALANCING_MEMORY_TIERING,
};

#ifdef CONFIG_BPF_NUMAB
extern struct static_key_false numab_cgroup_mode_set;

int task_numab_mode(struct task_struct *p);
int folio_numab_mode(struct folio *folio);
void numab_memcg_reset(struct mem_cgroup *memcg);
#endif

/*
 * Whether any task might need the NUMA scanner on this tick.  This is
 * only the cheap global gate; the per-task request is checked after the
 * scan period in task_tick_numa().
 */
static inline bool task_numab_tick_possible(void)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_likely(&numab_cgroup_mode_set))
		return true;
#endif
	return static_branch_unlikely(&sched_numa_balancing);
}

/*
 * Whether NUMA balancing applies to @p: the global sysctl state, possibly
 * overridden by the requests of @p's memcg and of every ancestor.
 * A memcg's request always takes priority over the system setting.
 */
static inline bool task_numab_enabled(struct task_struct *p)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = task_numab_mode(p);

		if (mode != NUMAB_FOLLOW_SYSTEM)
			return mode != NUMAB_DISABLED;
	}
#endif
	return static_branch_likely(&sched_numa_balancing);
}

/* Whether NUMA balancing is in memory tiering mode. */
static inline bool numab_in_tiering_mode(void)
{
	return sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING;
}

/*
 * Return both task-side decisions from one request lookup.  This is used
 * by paths that need to know both whether to account the fault and
 * whether slow-tier faults should be skipped.
 */
static inline void task_numab_get_modes(struct task_struct *p, bool *enabled,
					bool *tiering)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = task_numab_mode(p);

		if (mode != NUMAB_FOLLOW_SYSTEM) {
			*enabled = mode != NUMAB_DISABLED;
			*tiering = mode & NUMAB_TIERING;
			return;
		}
	}
#endif
	*enabled = static_branch_likely(&sched_numa_balancing);
	*tiering = numab_in_tiering_mode();
}

/*
 * The combined folio-side request, with the global sysctl state used when
 * no memcg requests a mode.  DISABLED never speaks for memory, so only
 * NORMAL and TIERING are present here.  Callers that need more than one
 * bit should use this helper once rather than querying each bit
 * separately.
 */
static inline int folio_numab_effective_mode(struct folio *folio)
{
#ifdef CONFIG_BPF_NUMAB
	if (static_branch_unlikely(&numab_cgroup_mode_set)) {
		int mode = folio_numab_mode(folio);

		if (mode != NUMAB_FOLLOW_SYSTEM)
			return mode;
	}
#endif
	return sysctl_numa_balancing_mode;
}

/*
 * Whether @folio's memory participates in tiering, i.e. whether its
 * _last_cpupid carries an access time instead of a cpupid. The
 * requests of the owner memcg and of every ancestor are combined.
 * DISABLED never speaks for memory (it is a task-side request), so only
 * NORMAL and TIERING are consulted here; without either, the global
 * sysctl decides.
 */
static inline bool folio_numab_in_tiering_mode(struct folio *folio)
{
	return folio_numab_effective_mode(folio) & NUMAB_TIERING;
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

static inline bool folio_numab_in_tiering_mode(struct folio *folio)
{
	return false;
}

static inline void task_numab_get_modes(struct task_struct *p, bool *enabled,
					bool *tiering)
{
	*enabled = false;
	*tiering = false;
}

static inline bool task_numab_tick_possible(void)
{
	return false;
}
#endif

#endif /* _LINUX_SCHED_NUMA_BALANCING_H */
