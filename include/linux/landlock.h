/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Internal cross subsystem header
 *
 * Copyright © 2026 Justin Suess <utilityemal77@gmail.com>
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <uapi/linux/landlock.h>

struct landlock_ruleset;

#ifdef CONFIG_SECURITY_LANDLOCK

/*
 * Returns an owned ruleset from a FD. It is thus needed to call
 * landlock_put_ruleset() on the returned value.
 */
struct landlock_ruleset *landlock_get_ruleset_from_fd(int fd, fmode_t mode);

/*
 * Acquires an additional reference to a ruleset if it is still alive.
 */
bool landlock_try_get_ruleset(struct landlock_ruleset *ruleset);

/*
 * Releases a previously acquired ruleset.
 */
void landlock_put_ruleset(struct landlock_ruleset *ruleset);

/*
 * Releases a previously acquired ruleset after an RCU-safe deferral.
 */
void landlock_put_ruleset_deferred(struct landlock_ruleset *ruleset);

/*
 * Restricts @cred with @ruleset and the supplied @flags.
 *
 * landlock_restrict_cred_precheck() must be called first.
 *
 * The caller owns @cred and is responsible for committing or aborting it.
 * @ruleset may be NULL only with LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF.
 */
int landlock_restrict_cred_precheck(__u32 flags, bool in_task_context);

int landlock_restrict_cred(struct cred *cred, struct landlock_ruleset *ruleset,
			   __u32 flags);

#else /* !CONFIG_SECURITY_LANDLOCK */

static inline struct landlock_ruleset *
landlock_get_ruleset_from_fd(int fd, fmode_t mode)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline bool landlock_try_get_ruleset(struct landlock_ruleset *ruleset)
{
	return false;
}

static inline void landlock_put_ruleset(struct landlock_ruleset *ruleset)
{
}

static inline void
landlock_put_ruleset_deferred(struct landlock_ruleset *ruleset)
{
}

static inline int landlock_restrict_cred(struct cred *cred,
					 struct landlock_ruleset *ruleset,
					 __u32 flags)
{
	return -EOPNOTSUPP;
}

static inline int landlock_restrict_cred_precheck(__u32 flags,
					 bool in_task_context)
{
	return -EOPNOTSUPP;
}

#endif /* !CONFIG_SECURITY_LANDLOCK */

#endif /* _LINUX_LANDLOCK_H */
