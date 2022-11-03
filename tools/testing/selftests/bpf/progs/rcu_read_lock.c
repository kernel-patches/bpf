// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_tracing_net.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} map_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} map_b SEC(".maps");

__u32 user_data, key_serial, target_pid = 0;
__u64 flags, result = 0;

extern struct bpf_key *bpf_lookup_user_key(__u32 serial, __u64 flags) __ksym;
extern void bpf_key_put(struct bpf_key *key) __ksym;

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int cgrp_succ(void *ctx)
{
	struct task_struct *task;
	struct css_set *cgroups;
	struct cgroup *dfl_cgrp;
	long init_val = 2;
	long *ptr;

	task = bpf_get_current_task_btf();
	if (task->pid != target_pid)
		return 0;

	bpf_rcu_read_lock();
	cgroups = task->cgroups;
	dfl_cgrp = cgroups->dfl_cgrp;
	bpf_rcu_read_unlock();
	ptr = bpf_cgrp_storage_get(&map_a, dfl_cgrp, &init_val,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;
	ptr = bpf_cgrp_storage_get(&map_a, dfl_cgrp, 0, 0);
	if (!ptr)
		return 0;
	result = *ptr;
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_nanosleep")
int task_succ(void *ctx)
{
	struct task_struct *task, *real_parent;

	task = bpf_get_current_task_btf();
	if (task->pid != target_pid)
		return 0;

	bpf_rcu_read_lock();
	real_parent = task->real_parent;
	(void)bpf_task_storage_get(&map_b, real_parent, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("?iter.s/ipv6_route")
int dump_ipv6_route(struct bpf_iter__ipv6_route *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct fib6_info *rt = ctx->rt;
	const struct net_device *dev;
	struct fib6_nh *fib6_nh;
	unsigned int flags;
	struct nexthop *nh;

	if (rt == (void *)0)
		return 0;

	fib6_nh = &rt->fib6_nh[0];
	flags = rt->fib6_flags;

	nh = rt->nh;
	bpf_rcu_read_lock();
	if (rt->nh)
		fib6_nh = &nh->nh_info->fib6_nh;

	if (fib6_nh->fib_nh_gw_family) {
		flags |= RTF_GATEWAY;
		BPF_SEQ_PRINTF(seq, "%pi6 ", &fib6_nh->fib_nh_gw6);
	} else {
		BPF_SEQ_PRINTF(seq, "00000000000000000000000000000000 ");
	}

	dev = fib6_nh->fib_nh_dev;
	bpf_rcu_read_unlock();
	if (dev)
		BPF_SEQ_PRINTF(seq, "%08x %08x %08x %08x %8s\n", rt->fib6_metric,
			       rt->fib6_ref.refs.counter, 0, flags, dev->name);
	else
		BPF_SEQ_PRINTF(seq, "%08x %08x %08x %08x\n", rt->fib6_metric,
			       rt->fib6_ref.refs.counter, 0, flags);

	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int miss_lock(void *ctx)
{
	struct task_struct *task;
	struct css_set *cgroups;
	struct cgroup *dfl_cgrp;

	task = bpf_get_current_task_btf();
	bpf_rcu_read_lock();
	cgroups = task->cgroups;
	bpf_rcu_read_unlock();
	dfl_cgrp = cgroups->dfl_cgrp;
	bpf_rcu_read_unlock();
	(void)bpf_cgrp_storage_get(&map_a, dfl_cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int miss_unlock(void *ctx)
{
	struct task_struct *task;
	struct css_set *cgroups;
	struct cgroup *dfl_cgrp;

	bpf_rcu_read_lock();
	task = bpf_get_current_task_btf();
	bpf_rcu_read_lock();
	cgroups = task->cgroups;
	bpf_rcu_read_unlock();
	dfl_cgrp = cgroups->dfl_cgrp;
	(void)bpf_cgrp_storage_get(&map_a, dfl_cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int cgrp_incorrect_rcu_region(void *ctx)
{
	struct task_struct *task;
	struct css_set *cgroups;
	struct cgroup *dfl_cgrp;

	bpf_rcu_read_lock();
	task = bpf_get_current_task_btf();
	cgroups = task->cgroups;
	bpf_rcu_read_unlock();
	dfl_cgrp = cgroups->dfl_cgrp;
	(void)bpf_cgrp_storage_get(&map_a, dfl_cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int task_incorrect_rcu_region1(void *ctx)
{
	struct task_struct *task, *real_parent;

	task = bpf_get_current_task_btf();

	bpf_rcu_read_lock();
	real_parent = task->real_parent;
	bpf_rcu_read_unlock();
	(void)bpf_task_storage_get(&map_b, real_parent, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int task_incorrect_rcu_region2(void *ctx)
{
	struct task_struct *task, *real_parent;

	task = bpf_get_current_task_btf();

	bpf_rcu_read_lock();
	real_parent = task->real_parent;
	(void)bpf_task_storage_get(&map_b, real_parent, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (real_parent)
		bpf_rcu_read_unlock();
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int inproper_sleepable_helper(void *ctx)
{
	struct task_struct *task, *real_parent;
	struct pt_regs *regs;
	__u32 value = 0;
	void *ptr;

	task = bpf_get_current_task_btf();

	bpf_rcu_read_lock();
	real_parent = task->real_parent;
	regs = (struct pt_regs *)bpf_task_pt_regs(real_parent);
	if (!regs) {
		bpf_rcu_read_unlock();
		return 0;
	}

	ptr = (void *)PT_REGS_IP(regs);
	(void)bpf_copy_from_user_task(&value, sizeof(uint32_t), ptr, task, 0);
	user_data = value;
	(void)bpf_task_storage_get(&map_b, real_parent, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("?lsm.s/bpf")
int BPF_PROG(inproper_sleepable_kfunc, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct bpf_key *bkey;

	bpf_rcu_read_lock();
	bkey = bpf_lookup_user_key(key_serial, flags);
	bpf_rcu_read_unlock();
        if (!bkey)
                return -1;
        bpf_key_put(bkey);

        return 0;
}
