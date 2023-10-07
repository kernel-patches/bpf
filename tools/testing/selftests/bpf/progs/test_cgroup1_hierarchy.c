// SPDX-License-Identifier: GPL-2.0
//#endif
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

__u32 target_ancestor_level;
__u64 target_ancestor_cgid;
int target_pid, target_hid;

u64 bpf_task_cgroup1_id_within_hierarchy(struct task_struct *task, int hierarchy_id) __ksym;
u64 bpf_task_ancestor_cgroup1_id_within_hierarchy(struct task_struct *task, int hierarchy_id,
						 int ancestor_level) __ksym;

static int bpf_link_create_verify(int cmd)
{
	__u64 cgid, ancestor_cgid;
	struct task_struct *task;
	int ret = 0;

	if (cmd != BPF_LINK_CREATE)
		return 0;

	task = bpf_get_current_task_btf();
	/* Then it can run in parallel */
	if (task->pid != target_pid)
		return 0;

	/* Refuse it if its cgid or its ancestor's cgid is the target cgid */
	cgid = bpf_task_cgroup1_id_within_hierarchy(task, target_hid);
	if (cgid == target_ancestor_cgid)
		ret = -1;

	ancestor_cgid = bpf_task_ancestor_cgroup1_id_within_hierarchy(task, target_hid,
								      target_ancestor_level);
	if (ancestor_cgid == target_ancestor_cgid)
		ret = -1;
	return ret;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_run, int cmd, union bpf_attr *attr, unsigned int size)
{
	return bpf_link_create_verify(cmd);
}

SEC("lsm.s/bpf")
int BPF_PROG(lsm_s_run, int cmd, union bpf_attr *attr, unsigned int size)
{
	return bpf_link_create_verify(cmd);
}

SEC("fentry")
int BPF_PROG(fentry_run)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
