// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops.s/thp_get_order")
__failure __msg("attach to unsupported member thp_get_order of struct bpf_thp_ops")
int BPF_PROG(thp_sleepable, struct vm_area_struct *vma, enum bpf_thp_vma_type vma_type,
	     enum tva_type tva_type, unsigned long orders)
{
	return -1;
}

SEC(".struct_ops.link")
struct bpf_thp_ops vma_ops = {
	.thp_get_order = (void *)thp_sleepable,
};
