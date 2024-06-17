// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

struct random_type {
	u64 id;
	u64 ref;
};

struct alloc_type {
	u64 id;
	struct nested_type {
		u64 id;
	} n;
	struct random_type __kptr *r;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct alloc_type);
	__uint(max_entries, 1);
} array_map SEC(".maps");

SEC("tc")
__failure
__msg("R1 must have a fixed offset of 0 when passed to a OBJ_RELEASE/KF_RELEASE flagged BPF helper/kfunc which takes a void *")
int alloc_obj_release(void *ctx)
{
	struct alloc_type *a;

	a = bpf_obj_new(typeof(*a));
	if (!a) {
		return 0;
	}
	/* bpf_obj_drop_impl() takes a void *, so when we attempt to pass in
	 * something with a reg->off, it should be rejected as we expect to have
	 * the original pointer passed to the respective BPF helper unmodified.
	 */
	bpf_obj_drop(&a->n);
	return 0;
}

SEC("lsm.s/file_open")
__failure
__msg("R1 must have a fixed offset of 0 when passed to a OBJ_RELEASE/KF_RELEASE flagged BPF helper/kfunc which takes a void *")
int BPF_PROG(mem_obj_release, struct file *file)
{
	int ret;
	char *buf;

	buf = bpf_ringbuf_reserve(&ringbuf, PATH_MAX, 0);
	if (!buf)
		return 0;

	ret = bpf_d_path(&file->f_path, buf, PATH_MAX);
	if (ret <= 0) {
		bpf_ringbuf_discard(buf += 8, 0);
		return 0;
	}

	bpf_ringbuf_submit(buf += 8, 0);
	return 0;
}

SEC("tp_btf/task_newtask")
__failure
__msg("dereference of modified ptr_ ptr R1 off=44 disallowed")
__msg("R1 must have a fixed offset of 0 when passed to a OBJ_RELEASE/KF_RELEASE flagged BPF helper/kfunc which takes a void *")
int BPF_PROG(type_match_mismatch, struct task_struct *task,
	     u64 clone_flags)
{
	struct task_struct *acquired;

	acquired = bpf_task_acquire(bpf_get_current_task_btf());
	if (!acquired)
		return 0;

	bpf_task_release((struct task_struct *)&acquired->flags);
	return 0;
}

SEC("tp_btf/task_newtask")
__failure
__msg("kernel function bpf_task_acquire args#0 expected pointer to STRUCT task_struct")
int BPF_PROG(trusted_type_match_mismatch, struct task_struct *task,
	     u64 clone_flags)
{
	/* Passing a trusted pointer with incorrect offset will result in a type
	 * mismatch.
	 */
	bpf_task_acquire((struct task_struct *)&bpf_get_current_task_btf()->flags);
	return 0;
}

SEC("tp_btf/task_newtask")
__failure
__msg("variable trusted_ptr_ access var_off=(0x0; 0xffffffff) disallowed")
int BPF_PROG(trusted_type_match_mismatch_var_off, struct task_struct *task,
	     u64 clone_flags)
{
	u32 var_off = bpf_get_prandom_u32();
	task = bpf_get_current_task_btf();

	task = (void *)task + var_off;
	/* Passing a trusted pointer with an incorrect variable offset, type
	 * match will succeed due to reg->off == 0, but the later call to
	 * __check_ptr_off_reg should fail as it's responsible for checking
	 * reg->var_off.
	 */
	bpf_task_acquire(task);
	return 0;
}

SEC("tp_btf/task_newtask")
__failure
__msg("variable trusted_ptr_ access var_off=(0x0; 0xffffffffffffffff) disallowed")
int BPF_PROG(trusted_type_match_mismatch_neg_var_off, struct task_struct *task,
	     u64 clone_flags)
{
	s64 var_off = task->start_time;
	task = bpf_get_current_task_btf();

	bpf_assert_range(var_off, -64, 64);
	/* Need one bpf_throw() reference, otherwise BTF gen fails. */
	if (!task)
		bpf_throw(1);

	task = (void *)task + var_off;
	/* Passing a trusted pointer with an incorrect variable offset, type
	 * match will succeed due to reg->off == 0, but the later call to
	 * __check_ptr_off_reg should fail as it's responsible for checking
	 * reg->var_off.
	 */
	task = bpf_task_acquire(task);
	return 0;
}

char _license[] SEC("license") = "GPL";
