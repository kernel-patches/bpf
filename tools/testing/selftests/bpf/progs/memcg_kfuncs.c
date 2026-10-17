// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

/* in */
u64 cgid;
unsigned long reclaim_size;
int reclaim_swappiness;

/* out */
unsigned long usage;
unsigned long ev_low, ev_high, ev_max, ev_oom, ev_oom_kill;
unsigned long bad_memory_event;
unsigned long bad_vm_event;
unsigned long bad_page_state;
unsigned long neg_memory_event;
unsigned long neg_vm_event;
unsigned long root_usage;
long reclaim_ret;

static struct mem_cgroup *memcg_from_cgid(void)
{
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		return NULL;

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	bpf_cgroup_release(cgrp);
	return memcg;
}

SEC("syscall")
int memcg_query(void *ctx)
{
	struct mem_cgroup *memcg;

	memcg = memcg_from_cgid();
	if (!memcg)
		return 1;

	usage = bpf_mem_cgroup_usage(memcg);

	ev_low = bpf_mem_cgroup_memory_events(memcg,
		bpf_core_enum_value(enum memcg_memory_event, MEMCG_LOW));
	ev_high = bpf_mem_cgroup_memory_events(memcg,
		bpf_core_enum_value(enum memcg_memory_event, MEMCG_HIGH));
	ev_max = bpf_mem_cgroup_memory_events(memcg,
		bpf_core_enum_value(enum memcg_memory_event, MEMCG_MAX));
	ev_oom = bpf_mem_cgroup_memory_events(memcg,
		bpf_core_enum_value(enum memcg_memory_event, MEMCG_OOM));
	ev_oom_kill = bpf_mem_cgroup_memory_events(memcg,
		bpf_core_enum_value(enum memcg_memory_event, MEMCG_OOM_KILL));

	/* Out-of-range indices must be rejected with (unsigned long)-1. */
	bad_memory_event = bpf_mem_cgroup_memory_events(memcg,
		bpf_core_enum_value(enum memcg_memory_event, MEMCG_NR_MEMORY_EVENTS));
	bad_vm_event = bpf_mem_cgroup_vm_events(memcg,
		bpf_core_enum_value(enum vm_event_item, NR_VM_EVENT_ITEMS));
	bad_page_state = bpf_mem_cgroup_page_state(memcg, -1);
	/* Negative indices must not bypass the bounds checks. */
	neg_memory_event = bpf_mem_cgroup_memory_events(memcg, -1);
	neg_vm_event = bpf_mem_cgroup_vm_events(memcg, -1);

	bpf_put_mem_cgroup(memcg);
	return 0;
}

SEC("syscall")
int root_memcg_query(void *ctx)
{
	struct mem_cgroup *memcg;

	memcg = bpf_get_root_mem_cgroup();
	if (!memcg)
		return 1;

	root_usage = bpf_mem_cgroup_usage(memcg);

	bpf_put_mem_cgroup(memcg);
	return 0;
}

SEC("syscall")
int memcg_reclaim(void *ctx)
{
	struct mem_cgroup *memcg;

	memcg = memcg_from_cgid();
	if (!memcg)
		return 1;

	reclaim_ret = bpf_proactive_reclaim(memcg, reclaim_size,
					    reclaim_swappiness);

	bpf_put_mem_cgroup(memcg);
	return 0;
}
