// SPDX-License-Identifier: GPL-2.0
//#endif
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

__u64 ancestor_cgid;
int target_pid;

struct cgroup *bpf_cgroup_acquire_from_id_within_controller(u64 cgid, int ssid) __ksym;
u64 bpf_cgroup_id_from_task_within_controller(struct task_struct *task, int ssid) __ksym;
u64 bpf_cgroup_ancestor_id_from_task_within_controller(struct task_struct *task,
						       int ssid, int level) __ksym;
long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;

static int bpf_link_create_verify(int cmd, union bpf_attr *attr, unsigned int size, int ssid)
{
	struct cgroup *cgrp = NULL;
	struct task_struct *task;
	__u64 cgid, root_cgid;
	int ret = 0;

	if (cmd != BPF_LINK_CREATE)
		return 0;

	task = bpf_get_current_task_btf();
	/* Then it can run in parallel */
	if (target_pid != BPF_CORE_READ(task, pid))
		return 0;

	cgrp = bpf_cgroup_acquire_from_id_within_controller(ancestor_cgid, ssid);
	if (!cgrp)
		goto out;

	if (bpf_task_under_cgroup(task, cgrp))
		ret = -1;
	bpf_cgroup_release(cgrp);

	cgid = bpf_cgroup_id_from_task_within_controller(task, ssid);
	if (cgid != ancestor_cgid)
		ret = 0;

	/* The level of root cgroup is 0, and its id is always 1 */
	root_cgid = bpf_cgroup_ancestor_id_from_task_within_controller(task, ssid, 0);
	if (root_cgid != 1)
		ret = 0;

out:
	return ret;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_net_cls, int cmd, union bpf_attr *attr, unsigned int size)
{
	return bpf_link_create_verify(cmd, attr, size, net_cls_cgrp_id);
}

SEC("lsm.s/bpf")
int BPF_PROG(lsm_s_net_cls, int cmd, union bpf_attr *attr, unsigned int size)
{
	return bpf_link_create_verify(cmd, attr, size, net_cls_cgrp_id);
}

SEC("lsm/bpf")
int BPF_PROG(lsm_cpu, int cmd, union bpf_attr *attr, unsigned int size)
{
	return bpf_link_create_verify(cmd, attr, size, cpu_cgrp_id);
}

SEC("fentry")
int BPF_PROG(fentry_run)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
