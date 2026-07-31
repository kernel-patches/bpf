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
#include <uapi/linux/landlock.h>

#include "common.h"
#include "cred.h"
#include "domain.h"
#include "ruleset.h"
#include "setup.h"

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
#ifdef CONFIG_AUDIT
	/* Translates "off" and "on" flags to booleans. */
	const bool log_same_exec =
		!(flags & LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF);
	const bool log_new_exec =
		!!(flags & LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON);
	const bool log_subdomains =
		!(flags & LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF);
	const bool prev_log_subdomains = !llcred->log_subdomains_off;
#endif /* CONFIG_AUDIT */

	*restriction = (struct landlock_restriction){};

#ifdef CONFIG_AUDIT
	restriction->log_subdomains_off = !prev_log_subdomains ||
					  !log_subdomains;
#endif /* CONFIG_AUDIT */

	if (!ruleset)
		return 0;

	restriction->domain = landlock_merge_ruleset(llcred->domain, ruleset);
	if (IS_ERR(restriction->domain)) {
		const int err = PTR_ERR(restriction->domain);

		restriction->domain = NULL;
		return err;
	}

#ifdef CONFIG_AUDIT
	restriction->domain->hierarchy->log_same_exec = log_same_exec;
	restriction->domain->hierarchy->log_new_exec = log_new_exec;
	if ((!log_same_exec && !log_new_exec) || !prev_log_subdomains)
		restriction->domain->hierarchy->log_status =
			LANDLOCK_LOG_DISABLED;
#endif /* CONFIG_AUDIT */

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
#ifdef CONFIG_AUDIT
	llcred->log_subdomains_off = restriction->log_subdomains_off;
#endif /* CONFIG_AUDIT */

	if (!restriction->domain)
		return;

	/* Replaces the old domain. */
	landlock_put_ruleset(llcred->domain);
	llcred->domain = restriction->domain;
	restriction->domain = NULL;

#ifdef CONFIG_AUDIT
	llcred->domain_exec |= BIT(llcred->domain->num_layers - 1);
#endif /* CONFIG_AUDIT */
}

static void hook_cred_transfer(struct cred *const new,
			       const struct cred *const old)
{
	const struct landlock_cred_security *const old_llcred =
		landlock_cred(old);

	landlock_get_ruleset(old_llcred->domain);
	*landlock_cred(new) = *old_llcred;

#ifdef CONFIG_BPF_LSM
	/* Only bprm credentials own a staged restriction: never copied. */
	WARN_ON_ONCE(landlock_cred(new)->staged.domain);
	landlock_cred(new)->staged = (struct landlock_restriction){};
#endif /* CONFIG_BPF_LSM */
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

	landlock_put_ruleset_deferred(llcred->domain);

#ifdef CONFIG_BPF_LSM
	/* Releases a restriction staged for an aborted execution. */
	landlock_put_ruleset_deferred(llcred->staged.domain);
#endif /* CONFIG_BPF_LSM */
}

#ifdef CONFIG_AUDIT

static int hook_bprm_creds_for_exec(struct linux_binprm *const bprm)
{
	/* Resets for each execution. */
	landlock_cred(bprm->cred)->domain_exec = 0;
	return 0;
}

#endif /* CONFIG_AUDIT */

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, hook_cred_transfer),
	LSM_HOOK_INIT(cred_free, hook_cred_free),

#ifdef CONFIG_AUDIT
	LSM_HOOK_INIT(bprm_creds_for_exec, hook_bprm_creds_for_exec),
#endif /* CONFIG_AUDIT */
};

__init void landlock_add_cred_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}
