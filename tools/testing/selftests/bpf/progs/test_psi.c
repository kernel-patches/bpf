// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct mem_cgroup *bpf_get_mem_cgroup(struct cgroup_subsys_state *css) __ksym;
void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;
int bpf_out_of_memory(struct mem_cgroup *memcg, int order, bool wait_on_oom_lock,
		      const char *constraint_text__nullable) __ksym;
int bpf_psi_create_trigger(struct bpf_psi *bpf_psi, u64 cgroup_id,
			   u32 res, u32 threshold_us, u32 window_us) __ksym;

#define PSI_FULL 0x80000000

/* cgroup which will experience the high memory pressure */
u64 high_pressure_cgroup_id;

/* cgroup which will be deleted */
u64 deleted_cgroup_id;

/* cgroup which was actually freed */
u64 freed_cgroup_id;

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
void BPF_PROG(handle_psi_event, struct psi_trigger *t)
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

	bpf_out_of_memory(memcg, 0, true, constraint_name);

	bpf_put_mem_cgroup(memcg);
	bpf_cgroup_release(cgroup);
}

SEC("struct_ops.s/handle_cgroup_free")
void BPF_PROG(handle_cgroup_free, u64 cgroup_id)
{
	freed_cgroup_id = cgroup_id;
}

SEC(".struct_ops.link")
struct bpf_psi_ops test_bpf_psi = {
	.init = (void *)psi_init,
	.handle_psi_event = (void *)handle_psi_event,
	.handle_cgroup_free = (void *)handle_cgroup_free,
};
