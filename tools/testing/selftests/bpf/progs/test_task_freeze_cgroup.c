// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <linux/types.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;
struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

extern int bpf_cgroup_write_interface(struct cgroup *cgrp,
				      const char *name__str,
				      const struct bpf_dynptr *value_p,
				      loff_t off) __ksym __weak;

char freeze_val[] = "1";
char unthaw_val[] = "0";

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

	/* Update new_pid with current pid */
	if (bpf_task_under_cgroup(acquired, cgrp))
		new_pid = acquired->tgid;

out:
	if (cgrp)
		bpf_cgroup_release(cgrp);
	bpf_task_release(acquired);

	return 0;
}

/* Try to attach from parent to trigger the bpf lsm hook, so from
 * parent context we unthaw child cgroup.
 */
SEC("lsm/task_free")
int BPF_PROG(lsm_task_free, struct task_struct *task)
{
	return 0;
}

static int process_freeze_cgroup(int pid, int freeze)
{
	int ret = 0;
	struct task_struct *task;
	struct bpf_dynptr dyn_ptr;
	struct cgroup *cgrp = NULL;

	task = bpf_task_from_pid(pid);
	if (!task)
		return -EINVAL;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp) {
		ret = -EINVAL;
		goto out;
	}

	if (!bpf_task_under_cgroup(task, cgrp))
		goto out;

	if (freeze)
		bpf_dynptr_from_mem(freeze_val, sizeof(freeze_val), 0, &dyn_ptr);
	else
		bpf_dynptr_from_mem(unthaw_val, sizeof(unthaw_val), 0, &dyn_ptr);

	ret = bpf_cgroup_write_interface(cgrp, "cgroup.freeze", &dyn_ptr, 0);

out:
	if (cgrp)
		bpf_cgroup_release(cgrp);
	bpf_task_release(task);
	return ret;
}

SEC("lsm.s/bpf")
int BPF_PROG(lsm_freeze_cgroup, int cmd, union bpf_attr *attr, unsigned int size)
{
	int ret = 0;
	struct task_struct *task;
	struct cgroup *cgrp = NULL;

	if (cmd != BPF_LINK_CREATE)
		return 0;

	task = bpf_get_current_task_btf();
	if (parent_pid == task->pid) {
		/* Parent context: unthaw child */
		process_freeze_cgroup(monitor_pid, 0);
		return 0;
	}

	/* Nothing todo */
	if (!freeze)
		return 0;

	/* Child context */
	if (monitor_pid != task->pid)
		return 0;

	/* Ensure we are under the corresponding cgroup so we freeze
	 * current child from its context
	 */
	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		return 0;

	if (!bpf_task_under_cgroup(task, cgrp))
		goto out;

	/* Schedule freeze task and return -EPERM */
	ret = process_freeze_cgroup(monitor_pid, freeze);

	/* On error or 0 we return zero and we catch at
	 * user space if the cgroup was not frozen.
	 */
	ret = (ret > 0) ? -EPERM : 0;

	/* Reset for next calls */
	freeze = 0;
out:
	if (cgrp)
		bpf_cgroup_release(cgrp);
	return ret;
}

char _license[] SEC("license") = "GPL";
