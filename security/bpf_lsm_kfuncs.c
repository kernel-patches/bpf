// SPDX-License-Identifier: GPL-2.0

/* BPF kfuncs exposing LSM policy objects. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cfi.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>

#include "lsm.h"

__bpf_kfunc_start_defs();

/**
 * bpf_lsm_policy_release - Release a policy object reference
 * @object: policy object to release
 *
 * Release an acquired reference on a policy object.
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
BTF_ID_FLAGS(func, bpf_lsm_policy_release, KF_RELEASE)
BTF_KFUNCS_END(bpf_lsm_policy_kfunc_ids)

BTF_ID_LIST(bpf_lsm_policy_dtor_ids)
BTF_ID(struct, lsm_policy_object)
BTF_ID(func, bpf_lsm_policy_release_dtor)

/*
 * BPF_PROG_TYPE_LSM and BPF_PROG_TYPE_SYSCALL share their kfunc
 * lookup buckets with other program types, so restricting the policy
 * kfuncs requires a filter.
 */
static int bpf_lsm_policy_kfunc_filter(const struct bpf_prog *prog,
				       u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_lsm_policy_kfunc_ids, kfunc_id))
		return 0;

	switch (prog->type) {
	case BPF_PROG_TYPE_SYSCALL:
	case BPF_PROG_TYPE_LSM:
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
