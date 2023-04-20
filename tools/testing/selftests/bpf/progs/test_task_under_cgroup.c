// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Bytedance */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const volatile int local_pid;
int remote_pid;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cgroup_map SEC(".maps");

SEC("tp/syscalls/sys_enter_getuid")
int sysenter_getuid(const void *ctx)
{
	if (local_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	if (!bpf_task_under_cgroup(&cgroup_map, bpf_get_current_task_btf(), 0))
		return 0;

	remote_pid = local_pid;

	return 0;
}

char _license[] SEC("license") = "GPL";
