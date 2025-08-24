// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/get_suggested_order")
__failure __msg("Unreleased reference")
int BPF_PROG(unreleased_memcg, struct mm_struct *mm, struct vm_area_struct *vma__nullable,
	     u64 vma_flags, u64 tva_flags, int orders)
{
	struct mem_cgroup *memcg = bpf_mm_get_mem_cgroup(mm);

	/* The memcg should be released with bpf_put_mem_cgroup() */
	return memcg ? 0 : 1;
}
SEC(".struct_ops.link")
struct bpf_thp_ops memcg = {
	.get_suggested_order = (void *)unreleased_memcg,
};
