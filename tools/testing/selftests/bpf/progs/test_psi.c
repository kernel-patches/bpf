#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

/* cgroup which will experience the high memory pressure */
u64 high_pressure_cgroup_id;
u32 my_pid = 0;

/* last total full memory pressure value */
u64 last_mem_full_total = 0;

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct elem {
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} tw_map SEC(".maps");

static int psi_oom_work(struct bpf_map *map, void *key, void *value)
{
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;

	cgrp = bpf_cgroup_from_id(high_pressure_cgroup_id);
	if (!cgrp)
		return 0;

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (memcg) {
		bpf_out_of_memory(memcg, 0, BPF_OOM_FLAGS_WAIT_ON_OOM_LOCK);
		bpf_put_mem_cgroup(memcg);
	}

	bpf_cgroup_release(cgrp);
	return 0;
}

static void schedule_oom_work(void)
{
	struct task_struct *task;
	struct elem *val;
	int key = 0;

	task = bpf_task_from_pid(my_pid);
	if (task) {
		val = bpf_map_lookup_elem(&tw_map, &key);
		if (val)
			bpf_task_work_schedule_signal(task, &val->tw,
						      &tw_map, psi_oom_work);
		bpf_task_release(task);
	}
}

SEC("tp_btf/psi_avgs_work")
int BPF_PROG(psi_avgs, struct psi_group *group)
{
	u64 current_total;
	u64 growth;

	/* Monitor only a single target cgroup */
	if (group->cgroup_id != high_pressure_cgroup_id)
		return 0;

	/* Check for memory pressure */
	current_total = BPF_CORE_READ(group, total[PSI_MEM_FULL]);
	if (last_mem_full_total == 0) {
		last_mem_full_total = current_total;
		return 0;
	}

	growth = current_total - last_mem_full_total;
	last_mem_full_total = current_total;

	/* Declare an OOM if growth > 50ms within the update period */
	if (growth > 50000000)
		schedule_oom_work();

	return 0;
}
