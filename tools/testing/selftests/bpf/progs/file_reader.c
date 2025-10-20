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
int err, run_success = 0;
char *user_buf;
const char *user_ptr;
volatile const __u32 user_buf_sz;

static int validate_file_read(struct file *file);
static int task_work_callback(struct bpf_map *map, void *key, void *value);

SEC("lsm/file_open")
int on_open_expect_fault(void *c)
{
	struct bpf_dynptr dynptr;
	struct file *file;
	char *rbuf = NULL;
	int local_err = 1;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;

	if (bpf_dynptr_from_file(file, 0, &dynptr))
		goto out;

	rbuf = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!rbuf)
		goto out;

	local_err = bpf_dynptr_read(rbuf, user_buf_sz, &dynptr, 0, 0);
	if (local_err == -EFAULT) { /* Expect page fault */
		local_err = 0;
		run_success = 1;
	}
out:
	if (rbuf)
		bpf_ringbuf_discard(rbuf, 0);
	bpf_dynptr_file_discard(&dynptr);
	if (local_err)
		err = local_err;
	bpf_put_file(file);
	return 0;
}

SEC("lsm/file_open")
int on_open_validate_file_read(void *c)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct elem *work;
	int key = 0;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

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
	struct file *file = bpf_get_task_exe_file(task);

	if (!file)
		return 0;

	validate_file_read(file);
	bpf_put_file(file);
	return 0;
}

static int verify_dynptr_read(struct bpf_dynptr *ptr, u32 off, char *user_buf, u32 len)
{
	char *rbuf = NULL;
	int err = 1, i;

	rbuf = bpf_ringbuf_reserve(&ringbuf, len, 0);
	if (!rbuf)
		goto cleanup;

	if (bpf_dynptr_read(rbuf, len, ptr, off, 0))
		goto cleanup;

	/* Verify file contents read from BPF is the same as the one read from userspace */
	bpf_for(i, 0, len)
	{
		if (rbuf[i] != user_buf[i])
			goto cleanup;
	}
	err = 0;

cleanup:
	if (rbuf)
		bpf_ringbuf_discard(rbuf, 0);
	return err;
}

static int validate_file_read(struct file *file)
{
	struct bpf_dynptr dynptr;
	int local_err = 1, off;
	char *ubuf = NULL;

	if (bpf_dynptr_from_file(file, 0, &dynptr))
		goto cleanup_file;

	ubuf = bpf_ringbuf_reserve(&ringbuf, user_buf_sz, 0);
	if (!ubuf)
		goto cleanup_all;

	local_err = bpf_copy_from_user(ubuf, user_buf_sz, user_buf);
	if (local_err)
		goto cleanup_all;

	local_err = verify_dynptr_read(&dynptr, 0, ubuf, user_buf_sz);
	off = 1;
	local_err = local_err ?: verify_dynptr_read(&dynptr, off, ubuf + off, user_buf_sz - off);
	off = user_buf_sz - 1;
	local_err = local_err ?: verify_dynptr_read(&dynptr, off, ubuf + off, user_buf_sz - off);
	/* Read file with random offset and length */
	off = 4097;
	local_err = local_err ?: verify_dynptr_read(&dynptr, off, ubuf + off, 100);

	/* Adjust dynptr, verify read */
	local_err = local_err ?: bpf_dynptr_adjust(&dynptr, off, off + 1);
	local_err = local_err ?: verify_dynptr_read(&dynptr, 0, ubuf + off, 1);
	/* Can't read more than 1 byte */
	local_err = local_err ?: verify_dynptr_read(&dynptr, 0, ubuf + off, 2) == 0;
	/* Can't read with far offset */
	local_err = local_err ?: verify_dynptr_read(&dynptr, 1, ubuf + off, 1) == 0;
cleanup_all:
	if (ubuf)
		bpf_ringbuf_discard(ubuf, 0);
cleanup_file:
	bpf_dynptr_file_discard(&dynptr);
	if (local_err)
		err = local_err;
	else
		run_success = 1;
	return 0;
}
