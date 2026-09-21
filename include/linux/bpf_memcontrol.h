/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF policy hooks for the memory controller.
 *
 * A bpf_memcg_ops is attached to a cgroup.  A charge runs the policies of
 * that cgroup and of every ancestor, and the kernel combines what they
 * return.  BPF only picks between things the kernel already does.
 */
#ifndef _LINUX_BPF_MEMCONTROL_H
#define _LINUX_BPF_MEMCONTROL_H

#include <linux/types.h>
#include <linux/gfp_types.h>

struct mem_cgroup;
struct task_struct;

/*
 * What a policy can ask for when a cgroup is over memory.high.  The kernel
 * ORs them, so one policy cannot undo another.
 */
enum bpf_memcg_high_request {
	BPF_MEMCG_HIGH_NO_OPINION	= 0,
	/*
	 * Skip the inline reclaim and throttle.  The debt is kept and paid on
	 * the way back to userspace, where no kernel locks are held.
	 */
	BPF_MEMCG_HIGH_DEFER_INLINE	= 1U << 0,
};

#define BPF_MEMCG_HIGH_VALID_MASK	BPF_MEMCG_HIGH_DEFER_INLINE

/* Read-only snapshot.  Only values the caller already has. */
struct bpf_memcg_ctx {
	struct mem_cgroup	*memcg;			/* charged memcg */
	struct mem_cgroup	*memcg_over_limit;	/* NULL if none found */
	struct task_struct	*task;			/* current */
	u64			cgroup_id;
	u64			over_limit_cgroup_id;	/* 0 if none */
	u64			nr_pages_over_high;
	u32			gfp_flags;
};

struct bpf_memcg_ops {
	/**
	 * high_policy - say where memory.high should be enforced
	 * @ctx: snapshot of the charge
	 *
	 * Return: bits from enum bpf_memcg_high_request, or 0.  Other bits
	 * are dropped.
	 */
	u32 (*high_policy)(const struct bpf_memcg_ctx *ctx);
};

/*
 * Run every high_policy on @memcg's cgroup and its ancestors, and return the
 * combined request for the caller to act on.
 *
 * @memcg:	the memcg being charged, never NULL
 * @over_limit:	first memcg found over memory.high or swap.high, or NULL
 * @gfp_mask:	the charge's gfp mask
 */
u32 bpf_memcg_high_policy(struct mem_cgroup *memcg,
			  struct mem_cgroup *over_limit, gfp_t gfp_mask);

#endif /* _LINUX_BPF_MEMCONTROL_H */
