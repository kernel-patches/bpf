// SPDX-License-Identifier: GPL-2.0

/* BPF kfuncs exposing LSM policy objects. */

#include <linux/binfmts.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cfi.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/memcontrol.h>
#include <linux/sched/mm.h>
#include <linux/security.h>

#include "lsm.h"

/* The sleepable LSM hooks bpf_lsm_policy_apply_bprm() may be called from. */
BTF_SET_START(bpf_lsm_policy_bprm_hooks)
BTF_ID(func, bpf_lsm_bprm_creds_for_exec)
BTF_ID(func, bpf_lsm_bprm_creds_from_file)
BTF_SET_END(bpf_lsm_policy_bprm_hooks)

__bpf_kfunc_start_defs();

/**
 * bpf_lsm_policy_acquire - Acquire a reference on a shared policy object
 * @object: RCU-protected pointer to a policy object, e.g. loaded from
 *          a map kptr field under bpf_rcu_read_lock()
 *
 * Acquire a reference of its own on a policy object the program does
 * not own, so that any number of concurrent program executions can
 * use the object shared through one map kptr field, without emptying
 * it as bpf_kptr_xchg() would.  The returned reference stays valid
 * after bpf_rcu_read_unlock() and must be released with
 * bpf_lsm_policy_release().
 *
 * Return: A referenced policy object, or NULL if the object's
 * reference count concurrently dropped to zero.
 */
__bpf_kfunc struct lsm_policy_object *
bpf_lsm_policy_acquire(struct lsm_policy_object *object)
{
	struct lsm_static_call *scall;

	lsm_for_each_hook(scall, policy_object_get) {
		if (scall->hl->lsmid->id != object->lsmid)
			continue;
		if (scall->hl->hook.policy_object_get(object))
			return NULL;
		return object;
	}
	return NULL;
}

/**
 * bpf_lsm_policy_apply_bprm - Apply a policy object to exec credentials
 * @object: policy object to apply
 * @bprm: execution context providing the prepared credentials to
 *        restrict
 * @flags: flags defined by the LSM owning @object
 *
 * Ask the LSM owning @object to restrict the credentials prepared in
 * @bprm with it, so that the executed task starts confined by the
 * policy.  How the policy composes with restrictions the credentials
 * already carry, and the meaning of @flags, are defined by the owning
 * LSM.  @object is only borrowed: the caller keeps its reference.
 * The hook runs in a root memcg charging scope: policy the LSM
 * computes on behalf of the program is not charged to the mediated
 * task.
 *
 * Return: 0 on success, -EOPNOTSUPP if the LSM owning @object does
 * not support applying policy to an execution, -EINVAL on unsupported
 * @flags, other negative values on LSM-specific failures.
 */
__bpf_kfunc int bpf_lsm_policy_apply_bprm(struct lsm_policy_object *object,
					  struct linux_binprm *bprm, u32 flags)
{
	struct lsm_static_call *scall;
	struct mem_cgroup *old_memcg;
	int err;

	lsm_for_each_hook(scall, bprm_apply_policy_object) {
		if (scall->hl->lsmid->id != object->lsmid)
			continue;
		/*
		 * The hook runs on behalf of the BPF program, not of the
		 * mediated task: charge its allocations to the root memcg.
		 */
		old_memcg = set_active_memcg(root_mem_cgroup);
		err = scall->hl->hook.bprm_apply_policy_object(bprm, object,
							       flags);
		set_active_memcg(old_memcg);
		return err;
	}
	return -EOPNOTSUPP;
}

/**
 * bpf_lsm_policy_from_fd - Get an LSM policy object from a fd
 * @fd: file descriptor referring to a policy object, resolved in the
 *      file descriptor table of the task running the program
 * @flags: reserved for future use, must be 0
 *
 * Translate @fd, as set up through the owning LSM's own userspace
 * interface, into a referenced policy object.  The fd identifies the
 * LSM asked to translate it: each LSM recognizes its own fds and
 * declines every other.  Only syscall programs may call this kfunc:
 * they run in the context of the task invoking them, where the fd is
 * meaningful.  The reference must be released with
 * bpf_lsm_policy_release().
 *
 * Return: A referenced policy object, or NULL if @flags is not 0, if
 * no enabled LSM recognizes @fd as one of its policy objects, or if
 * the recognizing LSM fails to translate it.
 */
__bpf_kfunc struct lsm_policy_object *bpf_lsm_policy_from_fd(int fd, u32 flags)
{
	struct lsm_static_call *scall;
	struct lsm_policy_object *object;
	int err;

	if (flags)
		return NULL;

	lsm_for_each_hook(scall, policy_object_from_fd) {
		err = scall->hl->hook.policy_object_from_fd(fd, &object);
		if (err == -EOPNOTSUPP)
			/* Not this LSM's fd: let another claim it. */
			continue;
		if (err)
			return NULL;
		return object;
	}
	return NULL;
}

/**
 * bpf_lsm_policy_release - Release a policy object reference
 * @object: policy object to release
 *
 * Release a reference acquired with bpf_lsm_policy_from_fd() or
 * bpf_lsm_policy_acquire().
 */
__bpf_kfunc void bpf_lsm_policy_release(struct lsm_policy_object *object)
{
	struct lsm_static_call *scall;

	lsm_for_each_hook(scall, policy_object_put) {
		if (scall->hl->lsmid->id != object->lsmid)
			continue;
		scall->hl->hook.policy_object_put(object);
		return;
	}
	/* A held reference implies the owning LSM implements the hook. */
	WARN_ON_ONCE(1);
}

/* Destructor for referenced lsm_policy_object kptrs. */
__bpf_kfunc void bpf_lsm_policy_release_dtor(void *object)
{
	bpf_lsm_policy_release(object);
}
CFI_NOSEAL(bpf_lsm_policy_release_dtor);

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_lsm_policy_kfunc_ids)
BTF_ID_FLAGS(func, bpf_lsm_policy_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_lsm_policy_apply_bprm, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_lsm_policy_from_fd,
	     KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_lsm_policy_release, KF_RELEASE)
BTF_KFUNCS_END(bpf_lsm_policy_kfunc_ids)

BTF_ID_LIST(bpf_lsm_policy_dtor_ids)
BTF_ID(struct, lsm_policy_object)
BTF_ID(func, bpf_lsm_policy_release_dtor)

BTF_ID_LIST_SINGLE(bpf_lsm_policy_apply_bprm_ids, func,
		   bpf_lsm_policy_apply_bprm)
BTF_ID_LIST_SINGLE(bpf_lsm_policy_from_fd_ids, func, bpf_lsm_policy_from_fd)

/*
 * BPF_PROG_TYPE_LSM and BPF_PROG_TYPE_SYSCALL share their kfunc
 * lookup buckets with other program types, so restricting the policy
 * kfuncs requires a filter.  A policy object fd is only meaningful in
 * the fd table of the task that set the object up: the fd kfunc is
 * exclusive to syscall programs, which run in that task's context.
 * Applying policy to an execution is exclusive to the sleepable bprm
 * LSM hooks the operation is specified for.
 */
static int bpf_lsm_policy_kfunc_filter(const struct bpf_prog *prog,
				       u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_lsm_policy_kfunc_ids, kfunc_id))
		return 0;

	switch (prog->type) {
	case BPF_PROG_TYPE_SYSCALL:
		if (kfunc_id == bpf_lsm_policy_apply_bprm_ids[0])
			return -EACCES;
		return 0;
	case BPF_PROG_TYPE_LSM:
		if (kfunc_id == bpf_lsm_policy_from_fd_ids[0])
			return -EACCES;

		if (kfunc_id == bpf_lsm_policy_apply_bprm_ids[0]) {
			/*
			 * BPF_LSM_CGROUP programs run under classic
			 * RCU and cannot sleep.
			 */
			if (prog->expected_attach_type == BPF_LSM_CGROUP)
				return -EACCES;

			if (!btf_id_set_contains(&bpf_lsm_policy_bprm_hooks,
						 prog->aux->attach_btf_id))
				return -EACCES;
		}

		return 0;
	default:
		return -EACCES;
	}
}

static const struct btf_kfunc_id_set bpf_lsm_policy_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_lsm_policy_kfunc_ids,
	.filter = bpf_lsm_policy_kfunc_filter,
};

static int __init bpf_lsm_policy_kfunc_init(void)
{
	const struct btf_id_dtor_kfunc bpf_lsm_policy_dtors[] = {
		{
			.btf_id = bpf_lsm_policy_dtor_ids[0],
			.kfunc_btf_id = bpf_lsm_policy_dtor_ids[1],
		},
	};
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
					&bpf_lsm_policy_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					       &bpf_lsm_policy_kfunc_set);
	return ret ?: register_btf_id_dtor_kfuncs(bpf_lsm_policy_dtors,
						  ARRAY_SIZE(bpf_lsm_policy_dtors),
						  THIS_MODULE);
}
late_initcall(bpf_lsm_policy_kfunc_init);
