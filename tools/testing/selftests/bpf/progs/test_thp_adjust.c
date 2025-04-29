// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define MM_BPF_ALLOWABLE        (1)
#define MM_BPF_NOT_ALLOWABLE    (-1)

int target_pid;

SEC("fmod_ret/mm_bpf_thp_vma_allowable")
int BPF_PROG(thp_vma_allowable, struct vm_area_struct *vma)
{
	struct task_struct *p;
	struct mm_struct *mm;

	if (!vma)
		return 0;

	mm = vma->vm_mm;
	if (!mm)
		return 0;

	p = mm->owner;
	/* The target task is not allowed to use THP. */
	if (p->pid == target_pid)
		return MM_BPF_NOT_ALLOWABLE;
	return 0;
}
