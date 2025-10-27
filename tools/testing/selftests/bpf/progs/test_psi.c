// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PSI_FULL 0x80000000

/* cgroup which will experience the high memory pressure */
u64 high_pressure_cgroup_id;

/* cgroup which will be deleted */
u64 deleted_cgroup_id;

/* cgroup which will be created */
u64 new_cgroup_id;

/* cgroup which was deleted */
u64 deleted_cgroup_id;

char constraint_name[] = "CONSTRAINT_BPF_PSI_MEM";

SEC("struct_ops.s/init")
int BPF_PROG(psi_init, struct bpf_psi *bpf_psi)
{
	int ret;

	ret = bpf_psi_create_trigger(bpf_psi, high_pressure_cgroup_id,
				     PSI_MEM | PSI_FULL, 100000, 1000000);
	if (ret)
		return ret;

	return bpf_psi_create_trigger(bpf_psi, deleted_cgroup_id,
				      PSI_IO, 100000, 1000000);
}

SEC("struct_ops.s/handle_psi_event")
void BPF_PROG(handle_psi_event, struct bpf_psi *bpf_psi, struct psi_trigger *t)
{
	u64 cgroup_id = t->cgroup_id;
	struct mem_cgroup *memcg;
	struct cgroup *cgroup;

	cgroup = bpf_cgroup_from_id(cgroup_id);
	if (!cgroup)
		return;

	memcg = bpf_get_mem_cgroup(&cgroup->self);
	if (!memcg) {
		bpf_cgroup_release(cgroup);
		return;
	}

	bpf_out_of_memory(memcg, 0, BPF_OOM_FLAGS_WAIT_ON_OOM_LOCK,
			  constraint_name);

	bpf_put_mem_cgroup(memcg);
	bpf_cgroup_release(cgroup);
}

SEC("struct_ops.s/handle_cgroup_online")
void BPF_PROG(handle_cgroup_online, struct bpf_psi *bpf_psi, u64 cgroup_id)
{
	new_cgroup_id = cgroup_id;

	bpf_psi_create_trigger(bpf_psi, cgroup_id, PSI_IO, 100000, 1000000);
}

SEC("struct_ops.s/handle_cgroup_offline")
void BPF_PROG(handle_cgroup_offline, struct bpf_psi *bpf_psi, u64 cgroup_id)
{
	deleted_cgroup_id = cgroup_id;
}

SEC(".struct_ops.link")
struct bpf_psi_ops test_bpf_psi = {
	.init = (void *)psi_init,
	.handle_psi_event = (void *)handle_psi_event,
	.handle_cgroup_online = (void *)handle_cgroup_online,
	.handle_cgroup_offline = (void *)handle_cgroup_offline,
};
