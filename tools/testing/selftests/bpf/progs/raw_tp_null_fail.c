// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

/* Ensure module parameter has PTR_MAYBE_NULL */
SEC("tp_btf/bpf_testmod_test_raw_tp_null_tp")
__success
int test_raw_tp_null_bpf_testmod_test_raw_tp_null_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

/* Check NULL marking */
SEC("tp_btf/sched_pi_setprio")
__success
int test_raw_tp_null_sched_pi_setprio_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/sched_pi_setprio")
__failure __log_level(2)
__msg("R1=untrusted_ptr_task_struct")
__msg("R1 must be a rcu pointer")
int BPF_PROG(trusted_or_null_walk_is_untrusted, struct task_struct *task,
	     struct task_struct *pi_task)
{
	struct task_struct *parent, *acquired;

	parent = pi_task->real_parent;
	acquired = bpf_task_acquire(parent);
	if (acquired)
		bpf_task_release(acquired);
	return 0;
}

SEC("tp_btf/sched_pi_setprio")
__failure __msg("R1 must be a rcu pointer")
int BPF_PROG(derived_ptr_null_check_does_not_restore_trust,
	     struct task_struct *task, struct task_struct *pi_task)
{
	struct task_struct *parent, *acquired;

	parent = pi_task->real_parent;
	if (!parent)
		return 0;

	acquired = bpf_task_acquire(parent);
	if (acquired)
		bpf_task_release(acquired);

	return 0;
}

/*
 * In contrast, checking the original trusted-or-NULL pointer removes
 * PTR_MAYBE_NULL while retaining PTR_TRUSTED.
 */
SEC("tp_btf/sched_pi_setprio")
__success
int BPF_PROG(original_ptr_null_check_retains_trust,
	     struct task_struct *task, struct task_struct *pi_task)
{
	struct task_struct *acquired;

	if (!pi_task)
		return 0;

	acquired = bpf_task_acquire(pi_task);
	if (acquired)
		bpf_task_release(acquired);

	return 0;
}
