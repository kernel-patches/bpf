/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF policy hooks for NUMA balancing.
 *
 * A bpf_numab_ops is attached to a cgroup. A NUMA balancing decision runs
 * the policies of that cgroup and of every ancestor, and the kernel combines
 * what they return. BPF only picks between things the kernel already does:
 * with global NUMA balancing disabled, a policy can enable it per workload;
 * with global NUMA balancing enabled, a policy can disable it for
 * latency-sensitive workloads or opt their memory into tiering.
 */
#ifndef _LINUX_BPF_NUMAB_H
#define _LINUX_BPF_NUMAB_H

#include <linux/types.h>

struct task_struct;
struct folio;

/*
 * What a policy can ask for NUMA balancing. The kernel ORs the requests
 * of all matching policies, so one policy cannot undo another's opt-in.
 * When several requests combine, the conservative choice wins:
 * BPF_NUMAB_DISABLED beats BPF_NUMAB_NORMAL, which beats BPF_NUMAB_TIERING.
 * A policy can always opt a workload out, so no cgroup is ever forced
 * into heavier machinery than its own policy asks for.
 *
 * The mode bits mirror the global sysctl_numa_balancing_mode semantics:
 * BPF_NUMAB_NORMAL asks for the normal mode, where hinting faults feed
 * the scheduler's NUMA statistics. BPF_NUMAB_TIERING asks for the
 * memory tiering mode, where the cgroup's non-top-tier memory records
 * access times in place of cpupids and is promoted when hot.
 * BPF_NUMAB_GLOBAL (0) makes no request and defers to the global sysctl
 * state.
 */
enum bpf_numab_mode {
	BPF_NUMAB_GLOBAL	= 0,
	BPF_NUMAB_DISABLED	= 1U << 0,
	BPF_NUMAB_NORMAL	= 1U << 1,
	BPF_NUMAB_TIERING	= 1U << 2,
};

#define BPF_NUMAB_VALID_MASK	(BPF_NUMAB_DISABLED | BPF_NUMAB_NORMAL | \
				 BPF_NUMAB_TIERING)

struct bpf_numab_ops {
	/**
	 * numab_mode - request a NUMA balancing mode
	 * @p: task the NUMA balancing machinery is about to act on, or NULL
	 * @folio: folio whose NUMA balancing semantics are being decided,
	 *	   or NULL
	 *
	 * Exactly one of @p and @folio is set. The kernel passes @p when
	 * it acts on a task (whether its scanner runs, whether a fault
	 * feeds its statistics) and @folio when it acts on a folio
	 * (whether its memory carries cpupids or access times, whether its
	 * top-tier pages are worth scanning). A policy must NULL-check
	 * before dereferencing.
	 *
	 * Called from the NUMA balancing hot paths (hinting faults,
	 * scanner passes, load balancing). It must not sleep.
	 *
	 * Return: bits from enum bpf_numab_mode.  Other bits are dropped.
	 */
	u32 (*numab_mode)(struct task_struct *p, struct folio *folio);
};

#if defined(CONFIG_CGROUP_BPF) && defined(CONFIG_NUMA_BALANCING)
u32 bpf_numab_mode(struct task_struct *p, struct folio *folio);
#else
static inline u32 bpf_numab_mode(struct task_struct *p, struct folio *folio)
{
	return BPF_NUMAB_GLOBAL;
}
#endif

#endif /* _LINUX_BPF_NUMAB_H */
