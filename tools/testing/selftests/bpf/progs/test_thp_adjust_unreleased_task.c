// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/get_suggested_order")
__failure __msg("Unreleased reference")
int BPF_PROG(unreleased_task, struct mm_struct *mm, struct vm_area_struct *vma__nullable,
	     u64 vma_flags, u64 tva_flags, int orders)
{
	struct task_struct *p = bpf_mm_get_task(mm);

	/* The task should be released with bpf_task_release() */
	return p ? 0 : 1;
}

SEC(".struct_ops.link")
struct bpf_thp_ops task = {
	.get_suggested_order = (void *)unreleased_task,
};
