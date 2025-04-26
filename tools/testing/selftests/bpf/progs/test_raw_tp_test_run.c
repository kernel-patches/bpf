// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u32 count = 0;
__u32 on_cpu = 0xffffffff;

static __always_inline int check_test_run(struct task_struct *task, char *comm)
{
	count++;
	if ((__u64) task == 0x1234ULL && (__u64) comm == 0x5678ULL) {
		on_cpu = bpf_get_smp_processor_id();
		return (long)task + (long)comm;
	}

	return 0;
}

SEC("raw_tp/task_rename")
int BPF_PROG(rename_raw_tp, struct task_struct *task, char *comm)
{
	return check_test_run(task, comm);
}

SEC("tp_btf/task_rename")
int BPF_PROG(rename_tp_btf, struct task_struct *task, char *comm)
{
	return check_test_run(task, comm);
}

char _license[] SEC("license") = "GPL";
