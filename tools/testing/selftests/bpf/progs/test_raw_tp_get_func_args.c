// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

__u64 test_result = 0;

static __always_inline int check_args(void *ctx, struct task_struct *task,
				      char *comm)
{
	__u64 cnt = bpf_get_func_arg_cnt(ctx);
	__u64 a = 0, b = 0, z = 0;
	__s64 err;

	if ((__u64)task != 0x1234ULL || (__u64)comm != 0x5678ULL)
		return 0;

	test_result = cnt == 2;

	/* valid arguments */
	err = bpf_get_func_arg(ctx, 0, &a);
	test_result &= err == 0 && a == 0x1234ULL;

	err = bpf_get_func_arg(ctx, 1, &b);
	test_result &= err == 0 && b == 0x5678ULL;

	/* not valid argument */
	err = bpf_get_func_arg(ctx, 2, &z);
	test_result &= err == -EINVAL;

	return a + b;
}

SEC("raw_tp/task_rename")
int BPF_PROG(raw_tp_test, struct task_struct *task, char *comm)
{
	return check_args(ctx, task, comm);
}

SEC("tp_btf/task_rename")
int BPF_PROG(tp_btf_test, struct task_struct *task, char *comm)
{
	return check_args(ctx, task, comm);
}

char _license[] SEC("license") = "GPL";
