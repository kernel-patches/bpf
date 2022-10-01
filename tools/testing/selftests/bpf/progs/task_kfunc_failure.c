// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

/* Prototype for all of the program trace events below:
 *
 * TRACE_EVENT(task_newtask,
 *         TP_PROTO(struct task_struct *p, u64 clone_flags)
 */

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_acquire_untrusted, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *acquired, *stack_ptr;

	if (!is_test_kfunc_task(task))
		return 0;

	/* Can't invoke bpf_task_acquire() on an untrusted, random pointer. */
	stack_ptr = (struct task_struct *)0xcafef00d;
	acquired = bpf_task_acquire(stack_ptr);
	bpf_task_release(acquired);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_acquire_null, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *acquired;

	if (!is_test_kfunc_task(task))
		return 0;

	/* Can't invoke bpf_task_acquire() on a NULL pointer. */
	acquired = bpf_task_acquire(NULL);
	bpf_task_release(acquired);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_acquire_unreleased, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *acquired;

	if (!is_test_kfunc_task(task))
		return 0;

	acquired = bpf_task_acquire(task);

	/* Acquired task is never released. */

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_get_non_kptr_param, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *kptr;

	/* Cannot use bpf_task_kptr_get() on a non-kptr, even on a valid task. */
	kptr = bpf_task_kptr_get(&task);
	if (!kptr)
		return 0;

	bpf_task_release(kptr);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_get_non_kptr_acquired, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *kptr, *acquired;

	acquired = bpf_task_acquire(task);

	/* Cannot use bpf_task_kptr_get() on a non-kptr, even if it was acquired. */
	kptr = bpf_task_kptr_get(&acquired);
	if (!kptr)
		return 0;

	bpf_task_release(kptr);
	bpf_task_release(acquired);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_get_null, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *kptr;

	/* Cannot use bpf_task_kptr_get() on a NULL pointer. */
	kptr = bpf_task_kptr_get(NULL);
	if (!kptr)
		return 0;

	bpf_task_release(kptr);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_xchg_unreleased, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *kptr;
	struct __tasks_kfunc_map_value *v;
	int status;

	if (!is_test_kfunc_task(task))
		return 0;

	status = tasks_kfunc_map_insert(task);
	if (status)
		return 0;

	v = tasks_kfunc_map_value_lookup(task);
	if (!v)
		return 0;

	kptr = bpf_kptr_xchg(&v->task, NULL);
	if (!kptr)
		return 0;


	/* Kptr retrieved from map is never released. */

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_get_unreleased, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *kptr;
	struct __tasks_kfunc_map_value *v;
	int status;

	if (!is_test_kfunc_task(task))
		return 0;

	status = tasks_kfunc_map_insert(task);
	if (status)
		return 0;

	v = tasks_kfunc_map_value_lookup(task);
	if (!v)
		return 0;

	kptr = bpf_task_kptr_get(&v->task);
	if (!kptr)
		return 0;


	/* Kptr acquired above is never released. */

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_release_untrusted, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *acquired = (struct task_struct *)0xcafef00d;

	if (!is_test_kfunc_task(task))
		return 0;

	/* Cannot release random on-stack pointer. */
	bpf_task_release(acquired);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_release_null, struct task_struct *task, u64 clone_flags)
{
	struct __tasks_kfunc_map_value local, *v;
	long status;
	struct task_struct *acquired, *old;
	s32 pid;

	if (!is_test_kfunc_task(task))
		return 0;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return 0;

	local.task = NULL;
	status = bpf_map_update_elem(&__tasks_kfunc_map, &pid, &local, BPF_NOEXIST);
	if (status)
		return status;

	v = bpf_map_lookup_elem(&__tasks_kfunc_map, &pid);
	if (!v)
		return status;

	acquired = bpf_task_acquire(task);
	old = bpf_kptr_xchg(&v->task, acquired);

	/* old cannot be passed to bpf_task_release() without a NULL check. */
	bpf_task_release(old);

	return 0;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(task_kfunc_release_unacquired, struct task_struct *task, u64 clone_flags)
{
	if (!is_test_kfunc_task(task))
		return 0;

	/* Cannot release trusted task pointer which was not acquired. */
	bpf_task_release(task);

	return 0;
}
