// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define THP_ALLOC_KHUGEPAGED (1<<1)

int target_pid;
int khugepaged_enter;

SEC("fentry/__khugepaged_enter")
int BPF_PROG(thp_run, struct mm_struct *mm)
{
	struct task_struct *current = bpf_get_current_task_btf();

	if (current->mm == mm && current->pid == target_pid)
		khugepaged_enter++;
	return 0;
}

SEC("struct_ops/allocator")
int BPF_PROG(bpf_thp_allocator)
{
	struct task_struct *current = bpf_get_current_task_btf();

	/* Allocate THP for this task in khugepaged. */
	if (current->pid == target_pid)
		return THP_ALLOC_KHUGEPAGED;
	return 0;
}

SEC(".struct_ops.link")
struct bpf_thp_ops thp = {
	.allocator = (void *)bpf_thp_allocator,
};
