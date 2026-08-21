// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - LSM policy object hooks
 *
 * Copyright © 2026 Justin Suess <utilityemal77@gmail.com>
 */

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <uapi/linux/landlock.h>

#include "bpf.h"
#include "cred.h"
#include "domain.h"
#include "limits.h"
#include "ruleset.h"
#include "setup.h"

#include <trace/events/landlock.h>

static int hook_bprm_apply_policy_object(struct linux_binprm *bprm,
					 struct lsm_policy_object *object,
					 u32 flags)
{
	struct landlock_cred_security *bprm_llcred = landlock_cred(bprm->cred);
	struct landlock_ruleset *ruleset;
	struct landlock_restriction restriction;
	int err;

	if (object->type != LANDLOCK_POLICY_TYPE_RULESET)
		return -EINVAL;

	ruleset = container_of(object, struct landlock_ruleset, policy_object);

	/*
	 * landlock_restrict_self(2) flags minus TSYNC, which targets
	 * the calling threads, not the execution.
	 */
	if ((flags | LANDLOCK_MASK_RESTRICT_BINPRM) !=
	    LANDLOCK_MASK_RESTRICT_BINPRM)
		return -EINVAL;

	err = landlock_prepare_restriction(bprm_llcred, ruleset, flags,
					   &restriction);
	if (err)
		return err;

	/*
	 * Replaces (and releases) a previously staged restriction.
	 * Nothing is enforced until bprm_committing_creds(); a failed
	 * execution drops the staged restriction in hook_cred_free().
	 */
	landlock_put_domain(bprm_llcred->staged.domain);
	bprm_llcred->staged = restriction;
	return 0;
}

static void hook_bprm_committing_creds(const struct linux_binprm *bprm)
{
	struct landlock_cred_security *bprm_llcred = landlock_cred(bprm->cred);
	struct landlock_domain *domain = bprm_llcred->staged.domain;

	if (!domain)
		return;

	/* Set first so the enforcement event reports the post-flag state. */
	if (bprm_llcred->staged.flags & LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS)
		task_set_no_new_privs(current);

	/* The application clears @staged's domain pointer. */
	landlock_apply_restriction(bprm_llcred, &bprm_llcred->staged);

	/*
	 * Past de_thread(), the process is single-threaded: this single
	 * event both concludes the operation and covers the whole
	 * process.
	 */
	trace_landlock_enforce_domain(domain, true, true,
				      task_no_new_privs(current));
}

static int hook_policy_object_from_fd(int fd, struct lsm_policy_object **object)
{
	struct landlock_ruleset *ruleset;

	ruleset = landlock_get_ruleset_from_fd(fd, FMODE_CAN_READ);
	if (IS_ERR(ruleset)) {
		if (ruleset == ERR_PTR(-EBADFD))
			return -EOPNOTSUPP;
		return PTR_ERR(ruleset);
	}

	*object = &ruleset->policy_object;
	return 0;
}

/*
 * The caller holds no reference, only an RCU-protected pointer: the
 * RCU-deferred ruleset free keeps the memory valid for the
 * inc_not_zero() race against a concurrent last put.
 */
static int hook_policy_object_get(struct lsm_policy_object *object)
{
	struct landlock_ruleset *ruleset;

	if (object->type != LANDLOCK_POLICY_TYPE_RULESET)
		return -EINVAL;

	ruleset = container_of(object, struct landlock_ruleset, policy_object);
	if (!refcount_inc_not_zero(&ruleset->usage))
		return -ENOENT;
	return 0;
}

static void hook_policy_object_put(struct lsm_policy_object *object)
{
	struct landlock_ruleset *ruleset;

	/*
	 * The type routes the container_of() resolution once several
	 * policy object types exist; only rulesets are referenced today.
	 */
	if (WARN_ON_ONCE(object->type != LANDLOCK_POLICY_TYPE_RULESET))
		return;

	ruleset = container_of(object, struct landlock_ruleset, policy_object);

	/*
	 * May be reached from BPF object destructors that cannot sleep,
	 * which is fine: the put queues the free as RCU work.
	 */
	landlock_put_ruleset(ruleset);
}

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_apply_policy_object, hook_bprm_apply_policy_object),
	LSM_HOOK_INIT(bprm_committing_creds, hook_bprm_committing_creds),
	LSM_HOOK_INIT(policy_object_from_fd, hook_policy_object_from_fd),
	LSM_HOOK_INIT(policy_object_get, hook_policy_object_get),
	LSM_HOOK_INIT(policy_object_put, hook_policy_object_put),
};

__init void landlock_add_bpf_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}
