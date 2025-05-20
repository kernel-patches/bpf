// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int target_pid;
int thp_calls;
int thp_wrong_calls;

SEC("fentry/do_huge_pmd_anonymous_page")
int BPF_PROG(thp_run)
{
	struct task_struct *current = bpf_get_current_task_btf();

	if (current->pid == target_pid)
		thp_calls++;
	else
		thp_wrong_calls++;
	return 0;
}

SEC("struct_ops/thp_bpf_allowable")
bool BPF_PROG(thp_bpf_allowable)
{
	struct task_struct *current = bpf_get_current_task_btf();

	/* Permit the current task to allocate memory using THP. */
	if (current->pid == target_pid)
		return true;
	return false;
}

SEC(".struct_ops.link")
struct bpf_thp_ops thp = {
	.thp_bpf_allowable = (void *)thp_bpf_allowable,
};
