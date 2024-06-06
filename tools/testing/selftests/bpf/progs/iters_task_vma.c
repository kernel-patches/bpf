// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

pid_t target_pid = 0;
unsigned int vmas_seen = 0;

struct {
	__u64 vm_start;
	__u64 vm_end;
} vm_ranges[1000];

SEC("raw_tp/sys_enter")
int iter_task_vma_for_each(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;
	unsigned int seen = 0;

	if (task->pid != target_pid)
		return 0;

	if (vmas_seen)
		return 0;

	bpf_for_each(task_vma, vma, task, 0) {
		/*
		 * Fast to verify, since 'seen' has the same range at every
		 * loop iteration.
		 */
		if (bpf_cmp_unlikely(seen, >=, 1000))
			break;

		vm_ranges[seen].vm_start = vma->vm_start;
		vm_ranges[seen].vm_end = vma->vm_end;
		seen++;
	}

	vmas_seen = seen;
	return 0;
}

SEC("raw_tp/sys_enter")
int iter_task_vma_for_each_eq(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;
	unsigned int seen = 0;

	if (task->pid != target_pid)
		return 0;

	if (vmas_seen)
		return 0;

	bpf_for_each(task_vma, vma, task, 0) {
		/*
		 * Also fast, since the verifier recognizes
		 * 0, 1, 2 != 1000 as [0, 999] range.
		 */
		if (bpf_cmp_unlikely(seen, ==, 1000))
			break;

		vm_ranges[seen].vm_start = vma->vm_start;
		vm_ranges[seen].vm_end = vma->vm_end;
		seen++;
	}

	vmas_seen = seen;
	return 0;
}

#define ARR_SZ 100000
char arr[ARR_SZ];

SEC("socket")
__success __flag(BPF_F_TEST_STATE_FREQ)
int loop_inside_iter(const void *ctx)
{
	struct bpf_iter_num it;
	int *v, sum = 0;
	__u64 i = 0;

	bpf_iter_num_new(&it, 0, ARR_SZ);
	while ((v = bpf_iter_num_next(&it))) {
		if (i < ARR_SZ)
			sum += arr[i++];
	}
	bpf_iter_num_destroy(&it);
	return sum;
}

SEC("socket")
__success __flag(BPF_F_TEST_STATE_FREQ)
int loop_inside_iter_signed(const void *ctx)
{
	struct bpf_iter_num it;
	int *v, sum = 0;
	long i = 0;

	bpf_iter_num_new(&it, 0, ARR_SZ);
	while ((v = bpf_iter_num_next(&it))) {
		if (i < ARR_SZ && i >= 0)
			sum += arr[i++];
	}
	bpf_iter_num_destroy(&it);
	return sum;
}

volatile const int limit = ARR_SZ;

SEC("socket")
__success __flag(BPF_F_TEST_STATE_FREQ)
int loop_inside_iter_volatile_limit(const void *ctx)
{
	struct bpf_iter_num it;
	int *v, sum = 0;
	__u64 i = 0;

	bpf_iter_num_new(&it, 0, ARR_SZ);
	while ((v = bpf_iter_num_next(&it))) {
		if (i < limit)
			sum += arr[i++];
	}
	bpf_iter_num_destroy(&it);
	return sum;
}

__noinline
static void touch_arr(int i)
{
	/*
	 * Though 'i' is signed the verifier sees that 0
	 * is the lowest number passed into static subprogram
	 * and determines the range [0, ARR_SZ - 1].
	 */
	if (i >= ARR_SZ)
		return;
	arr[i] = i;
}

__noinline
int touch_arr_global(__u32 i)
{
	/*
	 * In global function the array index 'i' has to be unsigned,
	 * otherwise the verifier will see unbounded min value.
	 */
	if (i >= ARR_SZ)
		return 0;
	arr[i] = i;
	return 0;
}

SEC("socket")
__success
int loop_inside_iter_subprog(const void *ctx)
{
	long i;

	for (i = 0; i <= 1000000 && can_loop; i++)
		touch_arr(i);

	for (i = 0; i <= 1000000 && can_loop; i++)
		touch_arr_global(i);

	return 0;
}
char _license[] SEC("license") = "GPL";
