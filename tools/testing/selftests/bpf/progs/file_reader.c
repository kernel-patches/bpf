// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "errno.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} arrmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10000000);
} ringbuf SEC(".maps");

struct elem {
	struct file *file;
	struct bpf_task_work tw;
};

int pid = 0;
int err;
char *user_buf;
const char *user_ptr;
volatile const __u32 user_buf_sz;

static int validate_file_read(struct task_struct *task, struct vm_area_struct *vma, void *data);
static int task_work_callback(struct bpf_map *map, void *key, void *value);
static int dynptr_file_read_fault(struct task_struct *task, struct vm_area_struct *vma, void *data);

SEC("raw_tp/sys_enter")
int on_getpid_expect_fault(void *c)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 1;

	/* Verify that in non-sleepable context read faults */
	bpf_find_vma(task, (unsigned long)user_ptr, dynptr_file_read_fault, NULL, 0);
	return 0;
}

/* Tries to read user_buf_sz bytes from file dynptr, returns read error */
static int dynptr_file_read_fault(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	struct bpf_dynptr dynptr;
	struct file *file = vma->vm_file;
	char *rbuf = NULL;
	int local_err = 1;

	if (!file) {
		err = 1;
		return 0;
	}

	if (bpf_dynptr_from_file(file, 0, &dynptr))
		goto out;

	rbuf = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!rbuf)
		goto out;

	local_err = bpf_dynptr_read(rbuf, user_buf_sz, &dynptr, 0, 0);
	local_err = local_err == -EFAULT ? 0 : 1; /* Expect page fault */
out:
	if (rbuf)
		bpf_ringbuf_discard(rbuf, 0);
	bpf_dynptr_file_discard(&dynptr);
	if (local_err)
		err = local_err;
	return 0;
}

SEC("raw_tp/sys_enter")
int on_getpid_validate_file_read(void *c)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct elem *work;
	int key = 0;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 1;

	work = bpf_map_lookup_elem(&arrmap, &key);
	if (!work) {
		err = 1;
		return 0;
	}
	bpf_task_work_schedule_signal(task, &work->tw, &arrmap, task_work_callback, NULL);
	return 0;
}

/* Called in a sleepable context, read 256K bytes, cross check with user space read data */
static int task_work_callback(struct bpf_map *map, void *key, void *value)
{
	struct task_struct *task = bpf_get_current_task_btf();

	bpf_find_vma(task, (unsigned long)user_ptr, validate_file_read, NULL, 0);
	return 0;
}

static int validate_file_read(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	struct bpf_dynptr dynptr;
	int local_err = 1, i;
	char *rbuf1 = NULL, *rbuf2 = NULL;
	struct file *file = vma->vm_file;

	if (!file) {
		err = 1;
		return 1;
	}

	if (bpf_dynptr_from_file(file, 0, &dynptr))
		goto cleanup_file;

	rbuf1 = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!rbuf1)
		goto cleanup_file;

	rbuf2 = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!rbuf2)
		goto cleanup_all;

	if (bpf_dynptr_read(rbuf1, user_buf_sz, &dynptr, 0, 0))
		goto cleanup_all;

	bpf_copy_from_user(rbuf2, user_buf_sz, user_buf);
	/* Verify file contents read from BPF is the same as the one read from userspace */
	bpf_for(i, 0, user_buf_sz)
	{
		if (i >= 256000 || rbuf1[i] != rbuf2[i])
			goto cleanup_all;
	}
	local_err = 0;

cleanup_all:
	if (rbuf1)
		bpf_ringbuf_discard(rbuf1, 0);
	if (rbuf2)
		bpf_ringbuf_discard(rbuf2, 0);
cleanup_file:
	bpf_dynptr_file_discard(&dynptr);
	if (local_err)
		err = local_err;
	return 0;
}
