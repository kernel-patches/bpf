// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "xdp_metadata.h"
#include "bpf_kfuncs.h"

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym __weak;
extern void bpf_task_release(struct task_struct *p) __ksym __weak;

__weak int subprog_btf_task_nullable(struct task_struct *task __arg_untrusted)
{
	if (!task)
		return 0;
	return task->pid + task->tgid;
}

SEC("?kprobe")
__success __log_level(2)
__msg("Validating subprog_btf_task_nullable() func#1...")
__msg(": R1=untrusted_ptr_or_null_task_struct(id=2) R10=fp0")
int btf_task_arg_nullable(void *ctx)
{
	struct task_struct *t = (void *)bpf_get_current_task();
	struct task_struct *untrusted = bpf_core_cast(t, struct task_struct);

	return subprog_btf_task_nullable(untrusted) + subprog_btf_task_nullable(NULL);
}

__weak int subprog_btf_task_nonnull(struct task_struct *task __arg_untrusted __arg_nonnull)
{
	return task->pid + task->tgid;
}

SEC("?kprobe")
__failure __log_level(2)
__msg("R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_")
__msg("Caller passes invalid args into func#1 ('subprog_btf_task_nonnull')")
int btf_task_arg_nonnull_fail1(void *ctx)
{
	return subprog_btf_task_nonnull(NULL);
}

SEC("?tp_btf/task_newtask")
__failure __log_level(2)
__msg("R1 type=ptr_or_null_ expected=ptr_, trusted_ptr_, rcu_ptr_")
__msg("Caller passes invalid args into func#1 ('subprog_btf_task_nonnull')")
int btf_task_arg_nonnull_fail2(void *ctx)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct task_struct *nullable;
	int res;

	nullable = bpf_task_acquire(t);

	 /* should fail, PTR_TO_BTF_ID_OR_NULL */
	res = subprog_btf_task_nonnull(nullable);

	if (nullable)
		bpf_task_release(nullable);

	return res;
}

SEC("?kprobe")
__success __log_level(2)
__msg("Validating subprog_btf_task_nonnull() func#1...")
__msg(": R1=untrusted_ptr_task_struct(id=2) R10=fp0")
int btf_task_arg_nonnull(void *ctx)
{
	struct task_struct *t = (void *)bpf_get_current_task();

	return subprog_btf_task_nonnull(bpf_core_cast(t, typeof(*t)));
}

__weak int subprog_nullable_trusted_task(struct task_struct *task __arg_trusted)
{
	char buf[16];

	if (!task)
		return 0;

	return bpf_copy_from_user_task(&buf, sizeof(buf), NULL, task, 0);
}

SEC("?uprobe.s")
__success __log_level(2)
__msg("Validating subprog_nullable_trusted_task() func#1...")
__msg(": R1=trusted_ptr_or_null_task_struct(id=1) R10=fp0")
int trusted_ptr_nullable(void *ctx)
{
	struct task_struct *t = bpf_get_current_task_btf();

	return subprog_nullable_trusted_task(t);
}

__weak int subprog_nonnull_trusted_task(struct task_struct *task __arg_trusted __arg_nonnull)
{
	char buf[16];

	return bpf_copy_from_user_task(&buf, sizeof(buf), NULL, task, 0);
}

SEC("?uprobe.s")
__success __log_level(2)
__msg("Validating subprog_nonnull_trusted_task() func#1...")
__msg(": R1=trusted_ptr_task_struct(id=1) R10=fp0")
int trusted_ptr_nonnull(void *ctx)
{
	struct task_struct *t = bpf_get_current_task_btf();

	return subprog_nonnull_trusted_task(t);
}

__weak int subprog_trusted_destroy(struct task_struct *task __arg_trusted)
{
	if (!task)
		return 0;

	bpf_task_release(task); /* should be rejected */

	return 0;
}

SEC("?tp_btf/task_newtask")
__failure __log_level(2)
__msg("release kernel function bpf_task_release expects refcounted PTR_TO_BTF_ID")
int BPF_PROG(trusted_destroy_fail, struct task_struct *task, u64 clone_flags)
{
	return subprog_trusted_destroy(task);
}

__weak int subprog_trusted_acq_rel(struct task_struct *task __arg_trusted)
{
	struct task_struct *owned;

	if (!task)
		return 0;

	owned = bpf_task_acquire(task);
	if (!owned)
		return 0;

	bpf_task_release(owned); /* this one is OK, we acquired it locally */

	return 0;
}

SEC("?tp_btf/task_newtask")
__success __log_level(2)
int BPF_PROG(trusted_acq_rel, struct task_struct *task, u64 clone_flags)
{
	return subprog_trusted_acq_rel(task);
}

char _license[] SEC("license") = "GPL";
