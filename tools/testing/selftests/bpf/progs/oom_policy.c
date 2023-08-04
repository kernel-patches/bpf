// SPDX-License-Identifier: GPL-2.0-only
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 24);
} cg_map SEC(".maps");

unsigned int victim_pid;
u64 victim_cg_id;

enum bpf_select_ret {
	BPF_SELECT_DISABLE,
	BPF_SELECT_TASK,
	BPF_SELECT_CHOSEN,
};

static __always_inline u64 task_cgroup_id(struct task_struct *task)
{
	struct kernfs_node *node;
	struct task_group *tg;

	if (!task)
		return 0;

	tg = task->sched_task_group;
	node = tg->css.cgroup->kn;

	return node->id;
}

SEC("fentry/oom_kill_process")
int BPF_PROG(oom_kill_process_k, struct oom_control *oc, const char *message)
{
	struct task_struct *victim = oc->chosen;

	if (!victim)
		return 0;

	victim_pid = victim->pid;
	victim_cg_id = task_cgroup_id(victim);
	return 0;
}

SEC("fmod_ret/bpf_select_task")
int BPF_PROG(select_task_test, struct oom_control *oc, struct task_struct *task, long points)
{
	u64 chosen_cg_id, task_cg_id;
	int chosen_cg_prio, task_cg_prio;
	struct task_struct *chosen;
	int *val;

	chosen = oc->chosen;
	chosen_cg_id = task_cgroup_id(chosen);
	task_cg_id = task_cgroup_id(task);
	chosen_cg_prio = task_cg_prio = 0;
	val = bpf_map_lookup_elem(&cg_map, &chosen_cg_id);
	if (val)
		chosen_cg_prio = *val;
	val = bpf_map_lookup_elem(&cg_map, &task_cg_id);
	if (val)
		task_cg_prio = *val;

	if (chosen_cg_prio > task_cg_prio)
		return BPF_SELECT_TASK;
	if (chosen_cg_prio < task_cg_prio)
		return BPF_SELECT_CHOSEN;

	return BPF_SELECT_DISABLE;

}

