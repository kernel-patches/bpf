// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int pid_not_eligible, pid_eligible;
int pmd_order;

SEC("struct_ops/thp_get_order")
int BPF_PROG(thp_eligible, struct vm_area_struct *vma, enum tva_type type,
	     unsigned long orders)
{
	struct mm_struct *mm = vma->vm_mm;
	int suggested_order = 0;
	struct task_struct *p;

	if (type != TVA_SMAPS)
		return 0;

	if (!mm)
		return 0;

	/* This BPF hook is already under RCU */
	p = mm->owner;
	if (!p || (p->pid != pid_eligible && p->pid != pid_not_eligible))
		return 0;

	if (p->pid == pid_eligible)
		suggested_order = pmd_order;
	else
		suggested_order = 30;	/* invalid order */
	return suggested_order;
}

SEC(".struct_ops.link")
struct bpf_thp_ops thp_eligible_ops = {
	.thp_get_order = (void *)thp_eligible,
};
