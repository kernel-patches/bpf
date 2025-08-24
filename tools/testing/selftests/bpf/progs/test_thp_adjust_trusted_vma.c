// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/get_suggested_order")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int BPF_PROG(thp_trusted_vma, struct mm_struct *mm, struct vm_area_struct *vma__nullable,
	     u64 vma_flags, u64 tva_flags, int orders)
{
	struct mem_cgroup *memcg = bpf_mm_get_mem_cgroup(vma__nullable->vm_mm);

	if (!memcg)
		return 0;

	bpf_put_mem_cgroup(memcg);
	return 1;
}
SEC(".struct_ops.link")
struct bpf_thp_ops thp_memcg_ops = {
	.get_suggested_order = (void *)thp_trusted_vma,
};
