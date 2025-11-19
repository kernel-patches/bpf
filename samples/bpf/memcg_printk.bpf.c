// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("struct_ops/try_charge_memcg")
int BPF_PROG(handle_try_charge_memcg, struct try_charge_memcg *tcm)
{
	bpf_printk(
		"memcg %s gfp_mask 0x%x nr_pages %lu reclaim_options 0x%lx\n",
		tcm->memcg->css.cgroup->kn->name,
		tcm->gfp_mask,
		tcm->nr_pages,
		tcm->reclaim_options);
	if (!tcm->charge_done)
		bpf_printk("memcg %s mem_over_limit %s\n",
			   tcm->memcg->css.cgroup->kn->name,
			   tcm->mem_over_limit->css.cgroup->kn->name);

	return 0;
}

SEC(".struct_ops")
struct memcg_ops mcg_ops = {
	.try_charge_memcg = (void *)handle_try_charge_memcg,
};

char _license[] SEC("license") = "GPL";
