// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "errno.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct cgroup_map_value {
	struct cgroup __kptr * cgrp;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct cgroup_map_value);
	__uint(max_entries, 1);
} stashed_cgroups SEC(".maps");

void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;

__u64 cgroup_kptr_nmi_id;
int cgroup_kptr_nmi_nr_cgrps;
int cgroup_kptr_nmi_inserted;
int cgroup_kptr_nmi_deleted;
int cgroup_kptr_nmi_killed_work_done;
int cgroup_kptr_nmi_clear_runs;
int cgroup_kptr_nmi_err;

SEC("syscall")
int insert_cgroup_kptr(void *ctx)
{
	struct cgroup_map_value init = {};
	struct cgroup_map_value *mapval;
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp, *old;
	__u32 key = 0;
	int nr_csses = 0;
	int i, ret;

	cgrp = bpf_cgroup_from_id(cgroup_kptr_nmi_id);
	if (!cgrp) {
		cgroup_kptr_nmi_err = -ENOENT;
		return 0;
	}

#pragma unroll
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		bpf_core_read(&css, sizeof(css), &cgrp->subsys[i]);
		if (css)
			nr_csses++;
	}

	ret = bpf_map_update_elem(&stashed_cgroups, &key, &init, BPF_NOEXIST);
	if (ret) {
		cgroup_kptr_nmi_err = ret;
		bpf_cgroup_release(cgrp);
		return 0;
	}

	mapval = bpf_map_lookup_elem(&stashed_cgroups, &key);
	if (!mapval) {
		cgroup_kptr_nmi_err = -ENOENT;
		bpf_cgroup_release(cgrp);
		bpf_map_delete_elem(&stashed_cgroups, &key);
		return 0;
	}

	/* After the fix the slot may be recycled with a stashed cgroup; drain it. */
	old = bpf_kptr_xchg(&mapval->cgrp, cgrp);
	if (old)
		bpf_cgroup_release(old);

	cgroup_kptr_nmi_inserted++;
	cgroup_kptr_nmi_clear_runs += nr_csses;

	return 0;
}

SEC("fexit/css_free_rwork_fn")
int BPF_PROG(mark_cgroup_killed_work_done, struct work_struct *work)
{
	struct cgroup_subsys_state *css;
	struct rcu_work *rwork;
	__u64 cgid;

	rwork = container_of(work, struct rcu_work, work);
	css = container_of(rwork, struct cgroup_subsys_state, destroy_rwork);
	if (!BPF_CORE_READ(css, ss))
		return 0;

	cgid = BPF_CORE_READ(css, cgroup, kn, id);
	if (cgid == cgroup_kptr_nmi_id)
		__sync_fetch_and_add(&cgroup_kptr_nmi_killed_work_done, 1);

	return 0;
}

SEC("tp_btf/nmi_handler")
int BPF_PROG(clear_cgroup_kptrs_from_nmi, void *handler, s64 delta_ns,
	     int handled)
{
	__u32 key = 0;

	if (cgroup_kptr_nmi_deleted >= cgroup_kptr_nmi_nr_cgrps)
		return 0;

	if (!bpf_map_delete_elem(&stashed_cgroups, &key))
		cgroup_kptr_nmi_deleted++;

	return 0;
}

char _license[] SEC("license") = "GPL";
