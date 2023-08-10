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
int failed_cnt;

#define	EOPNOTSUPP	95

enum {
	NO_BPF_POLICY,
	BPF_EVAL_ABORT,
	BPF_EVAL_NEXT,
	BPF_EVAL_SELECT,
};

extern void set_oom_policy_name(struct oom_control *oc, const char *buf, size_t sz) __ksym;

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

	if (victim) {
		victim_cg_id = task_cgroup_id(victim);
		victim_pid = victim->pid;
	}

	return 0;
}

SEC("fentry/bpf_set_policy_name")
int BPF_PROG(set_police_name_k, struct oom_control *oc)
{
	char name[] = "cg_prio";
	set_oom_policy_name(oc, name, sizeof(name));
	return 0;
}

SEC("tp_btf/select_bad_process_end")
int BPF_PROG(record_failed, struct oom_control *oc)
{
	failed_cnt += 1;
	return 0;
}

SEC("fmod_ret/bpf_oom_evaluate_task")
int BPF_PROG(bpf_oom_evaluate_task, struct task_struct *task, struct oom_control *oc)
{
	int chosen_cg_prio, task_cg_prio;
	u64 chosen_cg_id, task_cg_id;
	struct task_struct *chosen;
	int *val;

	if (!failed_cnt)
		return BPF_EVAL_NEXT;

	chosen = oc->chosen;
	if (!chosen)
		return BPF_EVAL_SELECT;

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
		return BPF_EVAL_SELECT;
	if (chosen_cg_prio < task_cg_prio)
		return BPF_EVAL_NEXT;

	return NO_BPF_POLICY;
}

