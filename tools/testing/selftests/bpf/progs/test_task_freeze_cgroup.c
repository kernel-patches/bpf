// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "bpf_misc.h"

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;
struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

int bpf_task_freeze_cgroup(struct task_struct *task, int freeze) __ksym;

const volatile int parent_pid;
const volatile int monitor_pid;
const volatile __u64 cgid;
int new_pid;
int freeze;

SEC("tp_btf/task_newtask")
int BPF_PROG(tp_newchild, struct task_struct *task, u64 clone_flags)
{
	struct cgroup *cgrp = NULL;
	struct task_struct *acquired;

	if (monitor_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	acquired = bpf_task_acquire(task);
	if (!acquired)
		return 0;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		goto out;

	if (bpf_task_under_cgroup(acquired, cgrp))
		new_pid = acquired->tgid;

out:
	if (cgrp)
		bpf_cgroup_release(cgrp);
	bpf_task_release(acquired);

	return 0;
}

/* This is attached from parent to trigger the bpf lsm hook, so parent
 * can unthaw the child.
 */
SEC("lsm/task_free")
int BPF_PROG(lsm_task_free, struct task_struct *task)
{
	return 0;
}

SEC("lsm.s/bpf")
int BPF_PROG(lsm_freeze_cgroup, int cmd, union bpf_attr *attr, unsigned int size)
{
	int ret = 0;
	struct cgroup *cgrp = NULL;
	struct task_struct *task;

	if (cmd != BPF_LINK_CREATE)
		return ret;

	task = bpf_get_current_task_btf();
	if (parent_pid == task->pid) {
		/* Unthaw child from parent */
		task = bpf_task_from_pid(monitor_pid);
		if (!task)
			return -ENOENT;

		ret = bpf_task_freeze_cgroup(task, 0);
		bpf_task_release(task);
		return ret;
	}

	if (monitor_pid != task->pid)
		return 0;

	/* Freeze the child cgroup from its context */
	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		goto out;

	if (!bpf_task_under_cgroup(task, cgrp))
		goto out;

	if (freeze) {
		/* Schedule freeze task and return -EPERM */
		ret = bpf_task_freeze_cgroup(task, 1);
		if (!ret) {
			ret = -EPERM;
			/* reset for next call */
			freeze = 0;
		}
	}
out:
	if (cgrp)
		bpf_cgroup_release(cgrp);
	return ret;
}

char _license[] SEC("license") = "GPL";
