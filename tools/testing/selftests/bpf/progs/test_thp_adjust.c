// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int pmd_order;

SEC("struct_ops/thp_get_order")
int BPF_PROG(thp_not_eligible, struct vm_area_struct *vma, enum tva_type type,
	     unsigned long orders)
{
	/* THPeligible in /proc/pid/smaps is 0 */
	if (type == TVA_SMAPS)
		return 0;
	return pmd_order;
}

SEC(".struct_ops.link")
struct bpf_thp_ops thp_eligible_ops = {
	.thp_get_order = (void *)thp_not_eligible,
};
