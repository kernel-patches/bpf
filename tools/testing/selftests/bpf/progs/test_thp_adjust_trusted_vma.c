// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/thp_get_order")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int BPF_PROG(thp_trusted_vma, struct vm_area_struct *vma, enum bpf_thp_vma_type vma_type,
	     enum tva_type tva_type, unsigned long orders)
{
	struct mm_struct *mm = vma->vm_mm;
	struct task_struct *p = mm->owner;

	if (!p)
		return 0;
	return -1;
}

SEC(".struct_ops.link")
struct bpf_thp_ops vma_ops = {
	.thp_get_order = (void *)thp_trusted_vma,
};
