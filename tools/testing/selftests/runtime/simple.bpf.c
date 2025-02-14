// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

void bpf_task_release(struct task_struct *p) __ksym;
struct task_struct *bpf_task_from_pid(s32 pid) __ksym;

struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;

SEC("syscall")
int test_simple(void *arg)
{
	struct task_struct *task;
	struct bpf_cpumask *cpumask;

	task = bpf_task_from_pid(1);
	if (!task)
		return 0;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		goto error_cpumask;

	bpf_cpumask_release(cpumask);
error_cpumask:
	bpf_task_release(task);

	return 0;
}
