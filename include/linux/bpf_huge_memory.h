/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __BPF_HUGE_MEMORY_H
#define __BPF_HUGE_MEMORY_H

#include <linux/cgroup-defs.h>

/**
 * struct bpf_mthp_ops - BPF callbacks for mTHP operations
 * @mthp_choose: Choose the custom mTHP orders
 *
 * This structure defines the interface for BPF programs to customize
 * mTHP behavior through struct_ops programs.
 */
struct bpf_mthp_ops {
	unsigned long (*mthp_choose)(struct cgroup *cgrp, unsigned long orders);
};

#ifdef CONFIG_BPF_TRANSPARENT_HUGEPAGE
/**
 * bpf_mthp_choose - Choose the custom mTHP orders using bpf
 * @mm: task mm_struct
 * @orders: original orders
 *
 * Return suited mTHP orders.
 */
unsigned long bpf_mthp_choose(struct mm_struct *mm, unsigned long orders);

/**
 * cgroup_bpf_set_mthp_ops - Set sub-cgroup mthp_ops to parent cgroup
 * @cgrp: want to set mthp_ops of sub-cgroup
 * @parent: parent cgroup
 */
static inline void cgroup_bpf_set_mthp_ops(struct cgroup *cgrp,
					   struct cgroup *parent)
{
	WRITE_ONCE(cgrp->mthp_ops, parent->mthp_ops);
}
#else
static inline unsigned long bpf_mthp_choose(struct mm_struct *mm,
					    unsigned long orders)
{
	return orders;
}
static inline void cgroup_bpf_set_mthp_ops(struct cgroup *cgrp,
					   struct cgroup *parent)
{
}
#endif /* CONFIG_BPF_TRANSPARENT_HUGEPAGE */

#endif /* __BPF_HUGE_MEMORY_H */

