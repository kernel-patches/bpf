// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Netflix, Inc.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

u64 bpf_task_get_cgroup_id(struct task_struct *task) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} pid_to_cgid_map SEC(".maps");

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
    u32 pid = prev->pid;
	u64 cgroup_id;

    cgroup_id = bpf_task_get_cgroup_id(prev);
    bpf_map_update_elem(&pid_to_cgid_map, &pid, &cgroup_id, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";