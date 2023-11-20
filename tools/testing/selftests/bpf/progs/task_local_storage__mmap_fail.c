// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_MMAPABLE);
	__type(key, int);
	__type(value, long);
} mmapable SEC(".maps");

__failure __msg("invalid access to map value, value_size=8 off=8 size=8")
SEC("tp_btf/sys_enter")
long BPF_PROG(fail_read_past_mapval_end, struct pt_regs *regs, long id)
{
	struct task_struct *task;
	long *ptr;
	long res;

	task = bpf_get_current_task_btf();
	if (!task)
		return 1;

	ptr = bpf_task_storage_get(&mmapable, task, 0, 0);
	if (!ptr)
		return 3;
	/* Although mmapable mapval is given an entire page, verifier shouldn't
	 * allow r/w past end of 'long' type
	 */
	res = *(ptr + 1);

	return res;
}
