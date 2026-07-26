// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - LSM policy kptr hooks
 *
 * Implementation of the LSM hooks backing the Landlock kfuncs
 *
 * Copyright © 2026 Justin Suess <utilityemal77@gmail.com>
 */

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/memcontrol.h>
#include <linux/sched/mm.h>
#include <uapi/linux/landlock.h>

#include "bpf.h"
#include "cred.h"
#include "limits.h"
#include "ruleset.h"
#include "setup.h"

static int hook_policy_kptr_from_fd(int fd, union lsm_policy_kptr *policy)
{
	struct landlock_ruleset *ruleset;

	ruleset = landlock_get_ruleset_from_fd(fd, FMODE_CAN_READ);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	policy->landlock.ruleset = (struct bpf_landlock_ruleset *)ruleset;
	return 0;
}

static void hook_policy_kptr_put(union lsm_policy_kptr *policy)
{
	struct landlock_ruleset *ruleset =
		(struct landlock_ruleset *)policy->landlock.ruleset;

	/*
	 * May be called from a BPF object destructor that cannot sleep,
	 * whereas dropping the last ruleset reference frees it and may
	 * sleep: always defer the free.
	 */
	landlock_put_ruleset_deferred(ruleset);
}

/* Charging scope for the BPF-driven domain allocations: root, i.e. nobody. */
static struct mem_cgroup *get_bpf_memcg(void)
{
#ifdef CONFIG_MEMCG
	return root_mem_cgroup;
#else
	return NULL;
#endif /* CONFIG_MEMCG */
}

static int hook_bprm_enforce_policy_kptr(struct linux_binprm *bprm,
					 union lsm_policy_kptr *policy,
					 u32 flags)
{
	struct landlock_cred_security *bprm_llcred = landlock_cred(bprm->cred);
	struct landlock_ruleset *ruleset =
		(struct landlock_ruleset *)policy->landlock.ruleset;
	struct landlock_restriction restriction;
	struct mem_cgroup *old_memcg;
	int err;

	/*
	 * Same flags as landlock_restrict_self(2), except
	 * LANDLOCK_RESTRICT_SELF_TSYNC: the restriction targets the
	 * execution, not the calling threads.
	 */
	if ((flags | LANDLOCK_MASK_RESTRICT_BINPRM) !=
	    LANDLOCK_MASK_RESTRICT_BINPRM)
		return -EINVAL;

	/*
	 * The domain confines the execution on behalf of the BPF
	 * program, not of the mediated task: do not charge the task's
	 * memcg for it.
	 */
	old_memcg = set_active_memcg(get_bpf_memcg());
	err = landlock_prepare_restriction(bprm_llcred, ruleset, flags,
					   &restriction);
	set_active_memcg(old_memcg);
	if (err)
		return err;

	/*
	 * Stages the restriction until the point of no return of the
	 * execution, replacing (and releasing) any previously staged
	 * one.  Nothing is enforced yet: an execution that fails before
	 * committing its credentials drops the staged restriction in
	 * hook_cred_free() with no effect on the calling task.
	 */
	landlock_put_ruleset(bprm_llcred->staged.domain);
	bprm_llcred->staged = restriction;
	return 0;
}

static void hook_bprm_committing_creds(const struct linux_binprm *bprm)
{
	struct landlock_cred_security *bprm_llcred = landlock_cred(bprm->cred);
	struct landlock_restriction restriction;

	if (!bprm_llcred->staged.domain)
		return;

	restriction = bprm_llcred->staged;
	bprm_llcred->staged = (struct landlock_restriction){};

	landlock_apply_restriction(bprm_llcred, &restriction);
}

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(policy_kptr_from_fd, hook_policy_kptr_from_fd),
	LSM_HOOK_INIT(policy_kptr_put, hook_policy_kptr_put),
	LSM_HOOK_INIT(bprm_enforce_policy_kptr, hook_bprm_enforce_policy_kptr),
	LSM_HOOK_INIT(bprm_committing_creds, hook_bprm_committing_creds),
};

__init void landlock_add_bpf_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}
