// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;
struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

int pf_alloc, pf_disallow, khugepaged_disallow;
struct mm_struct *target_mm;
int pmd_order, cgrp_id;

/* Detecting whether a task can successfully allocate THP is unreliable because
 * it may be influenced by system memory pressure. Instead of making the result
 * dependent on unpredictable factors, we should simply check
 * bpf_hook_thp_get_orders()'s return value, which is deterministic.
 */
SEC("fexit/bpf_hook_thp_get_orders")
int BPF_PROG(thp_run, struct vm_area_struct *vma, u64 vma_flags, enum tva_type tva_type,
	     unsigned long orders, int retval)
{
	struct mm_struct *mm = vma->vm_mm;

	if (mm != target_mm)
		return 0;

	if (orders != (1 << pmd_order))
		return 0;

	if (tva_type == TVA_PAGEFAULT) {
		if (retval == (1 << pmd_order))
			pf_alloc++;
		else if (retval == (1 << 0))
			pf_disallow++;
	} else if (tva_type == TVA_KHUGEPAGED) {
		/* khugepaged is not triggered immediately, so its allocation
		 * counts are unreliable.
		 */
		if (retval == (1 << 0))
			khugepaged_disallow++;
	}
	return 0;
}

SEC("struct_ops/thp_get_order")
int BPF_PROG(alloc_in_khugepaged, struct vm_area_struct *vma, enum bpf_thp_vma_type vma_type,
	     enum tva_type tva_type, unsigned long orders)
{
	struct mm_struct *mm = vma->vm_mm;
	struct task_struct *p, *acquired;
	int suggested_order = 0;
	struct cgroup *cgrp;

	if (orders != (1 << pmd_order))
		return 0;

	if (!mm)
		return 0;

	/* This BPF hook is already under RCU */
	p = mm->owner;
	if (!p)
		return 0;

	acquired = bpf_task_acquire(p);
	if (!acquired)
		return 0;

	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp) {
		bpf_task_release(acquired);
		return 0;
	}

	if (bpf_task_under_cgroup(acquired, cgrp)) {
		if (!target_mm)
			target_mm = mm;

		/* BPF THP allocation policy:
		 * - Allow PMD allocation in khugepagd only
		 * - "THPeligible" in /proc/<pid>/smaps is also set
		 */
		if (tva_type == TVA_KHUGEPAGED || tva_type == TVA_SMAPS)
			suggested_order = pmd_order;
	}
	bpf_cgroup_release(cgrp);
	bpf_task_release(acquired);
	return suggested_order;
}

SEC(".struct_ops.link")
struct bpf_thp_ops khugepaged_ops = {
	.thp_get_order = (void *)alloc_in_khugepaged,
};

SEC("struct_ops/thp_get_order")
int BPF_PROG(alloc_not_in_swap, struct vm_area_struct *vma, enum bpf_thp_vma_type vma_type,
	     enum tva_type tva_type, unsigned long orders)
{
	if (tva_type == TVA_SWAP)
		return 0;
	return -1;
}

SEC(".struct_ops.link")
struct bpf_thp_ops swap_ops = {
	.thp_get_order = (void *)alloc_not_in_swap,
};
