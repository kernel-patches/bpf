// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct large_value {
	__u8 data[16 * 1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct large_value);
} uprobe_storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct large_value);
} uprobe_multi_storage SEC(".maps");

int pid;
int uprobe_ok;
int uprobe_multi_ok;

SEC("uprobe")
int test_uprobe(struct pt_regs *ctx)
{
	struct task_struct *task;
	struct large_value *value;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	task = bpf_get_current_task_btf();
	value = bpf_task_storage_get(&uprobe_storage, task, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (value)
		uprobe_ok++;

	return 0;
}

SEC("uprobe.multi")
int test_uprobe_multi(struct pt_regs *ctx)
{
	struct task_struct *task;
	struct large_value *value;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	task = bpf_get_current_task_btf();
	value = bpf_task_storage_get(&uprobe_multi_storage, task, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (value)
		uprobe_multi_ok++;

	return 0;
}

char _license[] SEC("license") = "GPL";
