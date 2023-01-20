// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#include "nested_trust_common.h"

char _license[] SEC("license") = "GPL";

int pid, err;

static bool is_test_task(void)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;

	return pid == cur_pid;
}

SEC("tp_btf/task_newtask")
__success
int BPF_PROG(test_read_cpumask, struct task_struct *task, u64 clone_flags)
{
	if (!is_test_task())
		return 0;

	bpf_cpumask_test_cpu(0, task->cpus_ptr);
	return 0;
}
