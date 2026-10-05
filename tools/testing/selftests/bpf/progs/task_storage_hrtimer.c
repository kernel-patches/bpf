// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} task_storage SEC(".maps");

u32 target_tgid;
u64 seen;
u64 attempted;
u64 succeeded;
u64 failed;
u64 delete_errors;

SEC("tp_btf/hrtimer_start")
int BPF_PROG(on_hrtimer_start, struct hrtimer *timer,
	     enum hrtimer_mode mode, bool was_armed)
{
	struct task_struct *task;
	long *storage;

	if (bpf_get_current_pid_tgid() >> 32 != target_tgid)
		return 0;

	seen++;
	attempted++;
	task = bpf_get_current_task_btf();
	storage = bpf_task_storage_get(&task_storage, task, NULL,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage) {
		failed++;
		return 0;
	}

	if (bpf_task_storage_delete(&task_storage, task))
		delete_errors++;
	else
		succeeded++;

	return 0;
}
