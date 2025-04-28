// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

struct mem_cgroup *bpf_get_mem_cgroup(struct cgroup_subsys_state *css) __ksym;
void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;
int bpf_out_of_memory(struct mem_cgroup *memcg, int order) __ksym;

SEC("fmod_ret.s/bpf_handle_psi_event")
int BPF_PROG(test_psi_event, struct psi_trigger *t)
{
	struct cgroup *cgroup = NULL;
	struct mem_cgroup *memcg;
	u64 cgroup_id;

	if (!t->of || !t->of->kn) {
		bpf_out_of_memory(NULL, 0);
		return 1;
	}

	cgroup_id = t->of->kn->__parent->id;
	cgroup = bpf_cgroup_from_id(cgroup_id);
	if (!cgroup)
		return 0;

	memcg = bpf_get_mem_cgroup(&cgroup->self);
	if (!memcg) {
		bpf_cgroup_release(cgroup);
		return 0;
	}

	bpf_out_of_memory(memcg, 0);

	bpf_put_mem_cgroup(memcg);
	bpf_cgroup_release(cgroup);

	return 1;
}
