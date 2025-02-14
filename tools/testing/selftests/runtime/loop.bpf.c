// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

void bpf_task_release(struct task_struct *p) __ksym;
struct task_struct *bpf_task_from_pid(s32 pid) __ksym;

SEC("syscall")
int test_loop(void *arg)
{
	struct task_struct *task_loop;
	struct task_struct *task1;
	int *v;

	task1 = bpf_task_from_pid(1);

	struct bpf_iter_num it;

	bpf_iter_num_new(&it, 1, 3);
	while ((v = bpf_iter_num_next(&it))) {
		task_loop = bpf_task_from_pid(*v);
		if (task_loop)
			bpf_task_release(task_loop);
	}

	bpf_iter_num_destroy(&it);

	if (task1)
		bpf_task_release(task1);

	return 0;
}
