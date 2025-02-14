// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

void bpf_task_release(struct task_struct *p) __ksym;
struct task_struct *bpf_task_from_pid(s32 pid) __ksym;

int test = 5;

SEC("syscall")
int test_branch(void *arg)
{
	struct task_struct *task1;

	task1 = bpf_task_from_pid(1);

	if (test > 2) {
		struct task_struct *task2;

		task2 = bpf_task_from_pid(2);
		if (task2)
			bpf_task_release(task2);
	}

	if (test < 2) {
		struct task_struct *task3;

		task3 = bpf_task_from_pid(3);
		if (task3)
			bpf_task_release(task3);
	}

	if (task1)
		bpf_task_release(task1);

	return 0;
}
