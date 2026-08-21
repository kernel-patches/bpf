// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Credential hooks
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 * Copyright © 2024-2025 Microsoft Corporation
 */

#include <linux/binfmts.h>
#include <linux/bits.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <uapi/linux/landlock.h>

#include "common.h"
#include "cred.h"
#include "domain.h"
#include "ruleset.h"
#include "setup.h"

#include <trace/events/landlock.h>

/**
 * landlock_prepare_restriction - Compute a credential restriction
 *
 * @llcred: Landlock credentials to restrict: provides the parent domain and
 *          the previous log configuration.  Not modified.
 * @ruleset: Ruleset to enforce, or NULL for a log-configuration-only change.
 * @flags: landlock_restrict_self(2) flags.  The caller is responsible for
 *         validating them against the set of flags it supports.
 * @restriction: Computed restriction.  On success, holds a reference on
 *               @restriction->domain (if any), which
 *               landlock_apply_restriction() transfers to the restricted
 *               credentials.
 *
 * The restriction builds on @llcred's current state: the caller must apply
 * it to (or stage it for) these same credentials.
 *
 * Return: 0 on success, -errno on failure.
 */
int landlock_prepare_restriction(
	const struct landlock_cred_security *const llcred,
	struct landlock_ruleset *const ruleset, const u32 flags,
	struct landlock_restriction *const restriction)
{
	struct landlock_domain *new_dom;
#ifdef CONFIG_SECURITY_LANDLOCK_LOG
	/* Translates "off" and "on" flags to booleans. */
	const bool log_same_exec =
		!(flags & LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF);
	const bool log_new_exec =
		!!(flags & LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON);
	const bool prev_log_subdomains = !llcred->log_subdomains_off;
#endif /* CONFIG_SECURITY_LANDLOCK_LOG */

	*restriction = (struct landlock_restriction){
		.flags = flags,
	};

	if (!ruleset)
		return 0;

	mutex_lock(&ruleset->lock);
	new_dom = landlock_merge_ruleset(llcred->domain, ruleset);
	if (IS_ERR(new_dom)) {
		mutex_unlock(&ruleset->lock);
		return PTR_ERR(new_dom);
	}
	/*
	 * Emits the domain-creation event while @ruleset->lock is still
	 * held, right after the merge, so an eBPF program attached to
	 * the tracepoint reads the exact ruleset that was merged into
	 * the domain: a consistent snapshot that a concurrent
	 * landlock_add_rule() (which holds the same lock) cannot
	 * modify.
	 *
	 * This must not be delayed past the return of this function.
	 * Holding @ruleset->lock across
	 * landlock_restrict_sibling_threads() would hang: a sibling
	 * thread blocked in landlock_add_rule() on the same
	 * @ruleset->lock cannot run the task_work that thread-sync
	 * waits for (the lock wait is uninterruptible).  Emitting here
	 * keeps the lock off the thread-sync path.
	 *
	 * The trade-off is that the event fires for a domain that may
	 * never be enforced: a later (rare) thread-sync failure or an
	 * aborted execution drops it.  Those paths free the domain,
	 * which emits the matching free_domain event so the create/free
	 * pair stays balanced.
	 */
	trace_landlock_create_domain(new_dom, ruleset);
	mutex_unlock(&ruleset->lock);

#ifdef CONFIG_SECURITY_LANDLOCK_LOG
	new_dom->hierarchy->log_same_exec = log_same_exec;
	new_dom->hierarchy->log_new_exec = log_new_exec;
	/*
	 * The creation event fired above, so move the domain out of
	 * LANDLOCK_LOG_UNCOMMITTED: its free_domain event must fire
	 * too, even if the domain is dropped before being enforced.
	 * Audit logging may still be disabled (DISABLED); tracing
	 * observes it anyway.
	 */
	if ((!log_same_exec && !log_new_exec) || !prev_log_subdomains)
		new_dom->hierarchy->log_status = LANDLOCK_LOG_DISABLED;
	else
		new_dom->hierarchy->log_status = LANDLOCK_LOG_PENDING;
#endif /* CONFIG_SECURITY_LANDLOCK_LOG */

	restriction->domain = new_dom;
	return 0;
}

/**
 * landlock_apply_restriction - Enforce a computed restriction on credentials
 *
 * @llcred: Landlock credentials to restrict, exclusively owned by the caller
 *          (prepared and not yet committed).
 * @restriction: Restriction computed by landlock_prepare_restriction()
 *               against the same credential state; its domain reference is
 *               transferred to @llcred.
 *
 * Cannot fail, so that a caller may apply a restriction past its last point
 * of failure, e.g. an exec point of no return.
 */
void landlock_apply_restriction(struct landlock_cred_security *const llcred,
				struct landlock_restriction *const restriction)
{
#ifdef CONFIG_SECURITY_LANDLOCK_LOG
	if (restriction->flags & LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF)
		llcred->log_subdomains_off = true;
#endif /* CONFIG_SECURITY_LANDLOCK_LOG */

	if (!restriction->domain)
		return;

	/* Replaces the old domain. */
	landlock_put_domain(llcred->domain);
	llcred->domain = restriction->domain;
	restriction->domain = NULL;

#ifdef CONFIG_SECURITY_LANDLOCK_LOG
	llcred->domain_exec |= BIT(llcred->domain->num_layers - 1);
#endif /* CONFIG_SECURITY_LANDLOCK_LOG */
}

static void hook_cred_transfer(struct cred *const new,
			       const struct cred *const old)
{
	landlock_cred_copy(landlock_cred(new), landlock_cred(old));
}

static int hook_cred_prepare(struct cred *const new,
			     const struct cred *const old, const gfp_t gfp)
{
	hook_cred_transfer(new, old);
	return 0;
}

static void hook_cred_free(struct cred *const cred)
{
	struct landlock_cred_security *const llcred = landlock_cred(cred);

	landlock_put_domain_deferred(llcred->domain);

#ifdef CONFIG_BPF_LSM
	/* Releases a restriction staged for an aborted execution. */
	landlock_put_domain_deferred(llcred->staged.domain);
#endif /* CONFIG_BPF_LSM */
}

#ifdef CONFIG_SECURITY_LANDLOCK_LOG

static int hook_bprm_creds_for_exec(struct linux_binprm *const bprm)
{
	/* Resets for each execution. */
	landlock_cred(bprm->cred)->domain_exec = 0;
	return 0;
}

#endif /* CONFIG_SECURITY_LANDLOCK_LOG */

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, hook_cred_transfer),
	LSM_HOOK_INIT(cred_free, hook_cred_free),

#ifdef CONFIG_SECURITY_LANDLOCK_LOG
	LSM_HOOK_INIT(bprm_creds_for_exec, hook_bprm_creds_for_exec),
#endif /* CONFIG_SECURITY_LANDLOCK_LOG */
};

__init void landlock_add_cred_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}
