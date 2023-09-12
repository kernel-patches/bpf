// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
char _license[] SEC("license") = "GPL";

pid_t target_pid = 0;
int process_cnt = 0;
int css_task_cnt = 0;
int css_dec_cnt = 0;

char is_post_order;
u64 cg_id;
u64 last_cg_id;
u64 first_cg_id;

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
struct cgroup *bpf_cgroup_acquire(struct cgroup *cgrp) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int iter_task_for_each_sleep(void *ctx)
{
	struct task_struct *task;
	struct task_struct *cur_task = bpf_get_current_task_btf();

	if (cur_task->pid != target_pid)
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(process, task) {
		if (task->pid == target_pid)
			process_cnt += 1;
	}
	bpf_rcu_read_unlock();
	return 0;
}


SEC("?lsm/file_mprotect")
int BPF_PROG(iter_css_task_for_each)
{
	struct task_struct *task;
	struct task_struct *cur_task = bpf_get_current_task_btf();

	if (cur_task->pid != target_pid)
		return 0;

	struct cgroup *cgrp = bpf_cgroup_from_id(cg_id);

	if (cgrp == NULL)
		return 0;
	struct cgroup_subsys_state *css = &cgrp->self;

	bpf_for_each(css_task, task, css, CSS_TASK_ITER_PROCS) {
		if (!task)
			continue;
		if (task->pid == target_pid)
			css_task_cnt += 1;
	}
	bpf_cgroup_release(cgrp);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int iter_css_dec_for_each(const void *ctx)
{
	struct task_struct *cur_task = bpf_get_current_task_btf();

	if (cur_task->pid != target_pid)
		return 0;

	struct cgroup *cgrp = bpf_cgroup_from_id(cg_id);

	if (cgrp == NULL)
		return 0;
	struct cgroup_subsys_state *root = &cgrp->self;
	struct cgroup_subsys_state *pos = NULL;

	bpf_rcu_read_lock();
	if (is_post_order) {
		bpf_for_each(css_post, pos, root) {
			struct cgroup *cur_cgrp = pos->cgroup;

			css_dec_cnt += 1;
			if (cur_cgrp)
				last_cg_id = cur_cgrp->kn->id;
		}
	} else {
		bpf_for_each(css_pre, pos, root) {
			struct cgroup *cur_cgrp = pos->cgroup;

			css_dec_cnt += 1;
			if (cur_cgrp && !first_cg_id)
				first_cg_id = cur_cgrp->kn->id;
		}
	}
	bpf_rcu_read_unlock();
	bpf_cgroup_release(cgrp);
	return 0;
}

