// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} cgrp_map SEC(".maps");

SEC("lsm/bpf")
int BPF_PROG(lsm_run, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (cmd != BPF_LINK_CREATE)
		return 0;

	if (bpf_current_task_under_cgroup(&cgrp_map, 0 /* map index */))
		return -1;
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(fentry_run)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
