// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define TVA_IN_PF (1 << 1)

int pf_alloc, pf_disallow, khugepaged_alloc, khugepaged_disallow;
int cgrp_id, target_pid;

/* Detecting whether a task can successfully allocate THP is unreliable because
 * it may be influenced by system memory pressure. Instead of making the result
 * dependent on unpredictable factors, we should simply check
 * get_suggested_order()'s return value, which is deterministic.
 */
SEC("fexit/get_suggested_order")
int BPF_PROG(thp_run, struct mm_struct *mm, unsigned long tva_flags, int order, int retval)
{
	struct task_struct *current = bpf_get_current_task_btf();

	if (current->pid != target_pid || order != 9)
		return 0;

	if (tva_flags & TVA_IN_PF) {
		if (retval == 9)
			pf_alloc++;
		else if (!retval)
			pf_disallow++;
	} else {
		if (retval == 9)
			khugepaged_alloc++;
		else if (!retval)
			khugepaged_disallow++;
	}
	return 0;
}

SEC("struct_ops/get_suggested_order")
int BPF_PROG(bpf_suggested_order, struct mm_struct *mm, unsigned long tva_flags, int order)
{
	struct mem_cgroup *memcg = bpf_mm_get_mem_cgroup(mm);
	int suggested_order = order;

	/* Only works when CONFIG_MEMCG is enabled. */
	if (!memcg)
		return suggested_order;

	if (memcg->css.cgroup->kn->id == cgrp_id) {
		/* BPF THP allocation policy:
		 * - Disallow PMD allocation in page fault context
		 */
		if (tva_flags & TVA_IN_PF && order == 9) {
			suggested_order = 0;
			goto out;
		}
	}

out:
	bpf_put_mem_cgroup(memcg);
	return suggested_order;
}

SEC(".struct_ops.link")
struct bpf_thp_ops thp = {
	.get_suggested_order = (void *)bpf_suggested_order,
};
