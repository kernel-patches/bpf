// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern struct lsm_policy_object *
bpf_lsm_policy_acquire(struct lsm_policy_object *object) __ksym;
extern int bpf_lsm_policy_apply_bprm(struct lsm_policy_object *object,
				     struct linux_binprm *bprm,
				     u32 flags) __ksym;
extern struct lsm_policy_object *
bpf_lsm_policy_from_fd(int fd, u32 flags) __ksym;
extern void bpf_lsm_policy_release(struct lsm_policy_object *object) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

struct policy_slot {
	struct lsm_policy_object __kptr *object;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct policy_slot);
} policy_map SEC(".maps");

/*
 * The LSM policy kfuncs are limited to LSM and syscall programs by
 * the BPF-side kfunc filter: a tracing program calling one must fail
 * verification.
 */
SEC("tp_btf/task_newtask")
__failure __msg("calling kernel function bpf_lsm_policy_from_fd is not allowed")
int BPF_PROG(tracing_prog, struct task_struct *task, u64 clone_flags)
{
	struct lsm_policy_object *object;

	object = bpf_lsm_policy_from_fd(-1, 0);
	if (object)
		bpf_lsm_policy_release(object);
	return 0;
}

/*
 * The fd kfunc is exclusive to syscall programs: it must be rejected
 * in an LSM program, even on an allowed hook.
 */
SEC("lsm.s/bprm_creds_for_exec")
__failure __msg("calling kernel function bpf_lsm_policy_from_fd is not allowed")
int BPF_PROG(lsm_get, struct linux_binprm *bprm)
{
	struct lsm_policy_object *object;

	object = bpf_lsm_policy_from_fd(-1, 0);
	if (object)
		bpf_lsm_policy_release(object);
	return 0;
}

/*
 * The enforcement kfunc is exclusive to the sleepable bprm LSM
 * hooks: it must be rejected in a syscall program.
 */
SEC("syscall")
__failure __msg("calling kernel function bpf_lsm_policy_apply_bprm is not allowed")
int syscall_restrict(void *ctx)
{
	return bpf_lsm_policy_apply_bprm(NULL, NULL, 0);
}

/*
 * Any LSM attach point other than the sleepable bprm hooks must be
 * rejected for the enforcement kfunc.
 */
SEC("lsm.s/file_open")
__failure __msg("calling kernel function bpf_lsm_policy_apply_bprm is not allowed")
int BPF_PROG(wrong_hook, struct file *file)
{
	return bpf_lsm_policy_apply_bprm(NULL, NULL, 0);
}

/*
 * The enforcement kfunc may sleep: a non-sleepable program on an
 * allowed hook must be rejected.
 */
SEC("lsm/bprm_creds_for_exec")
__failure
__msg("program must be sleepable to call sleepable kfunc bpf_lsm_policy_apply_bprm")
int BPF_PROG(nonsleepable_prog, struct linux_binprm *bprm)
{
	return bpf_lsm_policy_apply_bprm(NULL, bprm, 0);
}

/* An acquired policy object reference must be released before returning. */
SEC("syscall")
__failure __msg("Unreleased reference")
int leak_policy(void *ctx)
{
	bpf_lsm_policy_from_fd(-1, 0);
	return 0;
}

/*
 * A kptr loaded outside an RCU read-side critical section is
 * untrusted: the acquire kfunc must reject it.
 */
SEC("lsm.s/file_open")
__failure __msg("must be a rcu pointer")
int BPF_PROG(acquire_untrusted, struct file *file)
{
	struct lsm_policy_object *object;
	struct policy_slot *slot;
	int key = 0;

	slot = bpf_map_lookup_elem(&policy_map, &key);
	if (!slot)
		return 0;

	object = slot->object;
	if (!object)
		return 0;

	object = bpf_lsm_policy_acquire(object);
	if (object)
		bpf_lsm_policy_release(object);
	return 0;
}

/* A reference acquired from a shared policy object must be released too. */
SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(leak_shared_policy, struct file *file)
{
	struct lsm_policy_object *object;
	struct policy_slot *slot;
	int key = 0;

	slot = bpf_map_lookup_elem(&policy_map, &key);
	if (!slot)
		return 0;

	bpf_rcu_read_lock();
	object = slot->object;
	if (object)
		object = bpf_lsm_policy_acquire(object);
	bpf_rcu_read_unlock();
	return 0;
}
