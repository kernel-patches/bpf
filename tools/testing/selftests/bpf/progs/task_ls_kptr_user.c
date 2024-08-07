// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

struct user_data {
	int a;
	int b;
	int result;
};

struct value_type {
	struct user_data __kptr_user *udata_mmap;
	struct user_data __kptr_user *udata;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct value_type);
} datamap SEC(".maps");

#define MAGIC_VALUE 0xabcd1234

/* This is a workaround to avoid clang generating a forward reference for
 * struct user_data. This is a known issue and will be fixed in the future.
 */
struct user_data __dummy;

pid_t child_pid = 0;
pid_t parent_pid = 0;

SEC("tp_btf/sys_enter")
int BPF_PROG(on_enter, struct pt_regs *regs, long id)
{
	struct task_struct *task, *data_task;
	struct value_type *ptr;
	struct user_data *udata;
	int acc;

	task = bpf_get_current_task_btf();
	if (task->pid != child_pid)
		return 0;

	data_task = bpf_task_from_pid(parent_pid);
	if (!data_task)
		return 0;

	ptr = bpf_task_storage_get(&datamap, data_task, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	bpf_task_release(data_task);
	if (!ptr)
		return 0;

	udata = ptr->udata_mmap;
	if (!udata)
		return 0;
	acc = udata->a + udata->b;

	udata = ptr->udata;
	if (!udata)
		return 0;
	udata->result = MAGIC_VALUE + udata->a + udata->b + acc;

	return 0;
}
