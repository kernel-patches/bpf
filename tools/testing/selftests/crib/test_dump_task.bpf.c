// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "test_dump_task.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 100000);
} rb SEC(".maps");

extern struct task_struct *bpf_task_from_vpid(pid_t vpid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
				 struct task_struct *task,
				 unsigned long addr) __ksym;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

SEC("crib")
int dump_all_vma(struct prog_args *arg)
{
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg->pid);
	if (!task) {
		err = -1;
		goto error;
	}

	struct vm_area_struct *cur_vma;
	struct bpf_iter_task_vma vma_it;

	bpf_iter_task_vma_new(&vma_it, task, 0);
	while ((cur_vma = bpf_iter_task_vma_next(&vma_it))) {
		struct event_vma *e_vma = bpf_ringbuf_reserve(&rb, sizeof(struct event_vma), 0);
		if (!e_vma) {
			err = -2;
			goto error_buf;
		}

		e_vma->hdr.type = EVENT_TYPE_VMA;
		e_vma->vm_start = BPF_CORE_READ(cur_vma, vm_start);
		e_vma->vm_end = BPF_CORE_READ(cur_vma, vm_end);
		e_vma->vm_flags = BPF_CORE_READ(cur_vma, vm_flags);

		if (cur_vma->vm_file)
			e_vma->vm_pgoff = BPF_CORE_READ(cur_vma, vm_pgoff);

		bpf_ringbuf_submit(e_vma, 0);
	}

error_buf:
	bpf_iter_task_vma_destroy(&vma_it);
	bpf_task_release(task);
error:
	return err;
}

SEC("crib")
int dump_task_stat(struct prog_args *arg)
{
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg->pid);
	if (!task) {
		err = -1;
		goto error;
	}

	struct event_task *e_task = bpf_ringbuf_reserve(&rb, sizeof(struct event_task), 0);
	if (!e_task) {
		err = -2;
		goto error_buf;
	}

	e_task->hdr.type = EVENT_TYPE_TASK;
	e_task->pid = BPF_CORE_READ(task, pid);
	e_task->prio = BPF_CORE_READ(task, prio);
	e_task->policy = BPF_CORE_READ(task, policy);
	e_task->flags = BPF_CORE_READ(task, flags);
	e_task->exit_code = BPF_CORE_READ(task, exit_code);
	BPF_CORE_READ_STR_INTO(&e_task->comm, task, comm);

	bpf_ringbuf_submit(e_task, 0);

	struct event_mm *e_mm = bpf_ringbuf_reserve(&rb, sizeof(struct event_mm), 0);
	if (!e_mm) {
		err = -2;
		goto error_buf;
	}

	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	e_mm->hdr.type = EVENT_TYPE_MM;
	e_mm->start_code = BPF_CORE_READ(mm, start_code);
	e_mm->end_code = BPF_CORE_READ(mm, end_code);
	e_mm->start_data = BPF_CORE_READ(mm, start_data);
	e_mm->end_data = BPF_CORE_READ(mm, end_data);
	e_mm->start_brk = BPF_CORE_READ(mm, start_brk);
	e_mm->brk = BPF_CORE_READ(mm, brk);
	e_mm->start_stack = BPF_CORE_READ(mm, start_stack);
	e_mm->arg_start = BPF_CORE_READ(mm, arg_start);
	e_mm->arg_end = BPF_CORE_READ(mm, arg_end);
	e_mm->env_start = BPF_CORE_READ(mm, env_start);
	e_mm->env_end = BPF_CORE_READ(mm, env_end);
	e_mm->map_count = BPF_CORE_READ(mm, map_count);

	bpf_ringbuf_submit(e_mm, 0);

error_buf:
	bpf_task_release(task);
error:
	return err;
}
