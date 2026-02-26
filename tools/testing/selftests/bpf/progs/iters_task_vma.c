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
		if (bpf_cmp_unlikely(seen, >=, 1000))
			break;

		vm_ranges[seen].vm_start = vma->vm_start;
		vm_ranges[seen].vm_end = vma->vm_end;
		seen++;
	}

	vmas_seen = seen;
	return 0;
}

unsigned int release_vmas_seen = 0;

SEC("fentry.s/" SYS_PREFIX "sys_getpgid")
int iter_task_vma_release_and_copy(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;
	unsigned int seen = 0;

	if (task->pid != target_pid)
		return 0;

	if (release_vmas_seen)
		return 0;

	bpf_for_each(task_vma, vma, task, 0) {
		__u64 start;
		char buf[8];

		if (bpf_cmp_unlikely(seen, >=, 1000))
			break;

		/* Phase 1: mmap_lock held, read VMA data */
		start = vma->vm_start;

		/* Transition: release mmap_lock */
		bpf_iter_task_vma_release(&___it);
		/* VMA pointer is now invalid; sleepable helpers allowed */

		/* Phase 2: mmap_lock released, sleepable call */
		bpf_copy_from_user(&buf, sizeof(buf), (void *)start);

		seen++;
	}

	release_vmas_seen = seen;
	return 0;
}

/*
 * Test nested task_vma iterators on the same task.  Both iterators take
 * mmap_read_trylock() on the same mm; the rwsem should allow the second
 * reader and the inner loop should observe at least one VMA.
 */
unsigned int nested_vmas_seen = 0;

SEC("fentry.s/" SYS_PREFIX "sys_getpgid")
int iter_task_vma_nested(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma1, *vma2;
	unsigned int seen = 0;

	if (task->pid != target_pid)
		return 0;

	if (nested_vmas_seen)
		return 0;

	bpf_for_each(task_vma, vma1, task, 0) {
		bpf_for_each(task_vma, vma2, task, 0) {
			seen++;
			break;
		}
		break;
	}

	nested_vmas_seen = seen;
	return 0;
}

char _license[] SEC("license") = "GPL";
