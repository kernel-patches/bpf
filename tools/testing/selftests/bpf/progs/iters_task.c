#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

pid_t target_pid = 0;
int process_cnt = 0;
int css_task_cnt = 0;
int css_dec_cnt = 0;

u64 cg_id;
u64 last_cg_id;

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
struct cgroup *bpf_cgroup_acquire(struct cgroup *cgrp) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;

SEC("?tp_btf/sys_enter")
int BPF_PROG(iter_task_for_each)
{
	struct task_struct *task;
	struct task_struct *cur_task = bpf_get_current_task_btf();

	if (cur_task->pid != target_pid)
		return 0;

	bpf_for_each(process, task)
		if (task->pid == target_pid)
			process_cnt += 1;

	return 0;
}

SEC("?tp_btf/sys_enter")
int iter_css_task_for_each(const void *ctx)
{
	struct task_struct *task;
	struct task_struct *cur_task = bpf_get_current_task_btf();

	if (cur_task->pid != target_pid)
		return 0;

	struct cgroup *cgrp = bpf_cgroup_from_id(cg_id);

	if (cgrp == NULL)
		return 0;
	struct cgroup_subsys_state *css = &cgrp->self;

	bpf_for_each(css_task, task, css, 0)
		if (task->pid == target_pid)
			css_task_cnt += 1;

	bpf_cgroup_release(cgrp);
	return 0;
}

SEC("?tp_btf/sys_enter")
int iter_css_dec_for_each(const void *ctx)
{
	struct task_struct *cur_task = bpf_get_current_task_btf();
	bool is_post_order = true;

	if (cur_task->pid != target_pid)
		return 0;

	struct cgroup *cgrp = bpf_cgroup_from_id(cg_id);

	if (cgrp == NULL)
		return 0;
	struct cgroup_subsys_state *root = &cgrp->self;
	struct cgroup_subsys_state *pos = NULL;

	bpf_for_each(css, pos, root, is_post_order) {
		struct cgroup *cur_cgrp = pos->cgroup;

		css_dec_cnt += 1;
		if (cur_cgrp)
			last_cg_id = cur_cgrp->kn->id;
	}
	bpf_cgroup_release(cgrp);
	return 0;
}
