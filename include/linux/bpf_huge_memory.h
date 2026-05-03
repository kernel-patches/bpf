/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __BPF_HUGE_MEMORY_H
#define __BPF_HUGE_MEMORY_H

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

#if defined(CONFIG_BPF_TRANSPARENT_HUGEPAGE) && defined(CONFIG_BPF_SYSCALL)
/**
 * bpf_mthp_choose: Choose the custom mTHP orders using bpf
 * @mm: task mm_struct
 * @orders: original orders
 *
 * Return suited mTHP orders.
 */
unsigned long bpf_mthp_choose(struct mm_struct *mm, unsigned long orders);
#else
static inline unsigned long bpf_mthp_choose(struct mm_struct *mm,
					    unsigned long orders)
{
	return orders;
}
#endif /* CONFIG_BPF_SYSCALL */

#endif /* __BPF_HUGE_MEMORY_H */

