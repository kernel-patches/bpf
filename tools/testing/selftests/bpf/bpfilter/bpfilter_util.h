/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BPFILTER_UTIL_H
#define BPFILTER_UTIL_H

#include <linux/bpfilter.h>
#include <linux/netfilter/x_tables.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline void init_entry_match(struct xt_entry_match *match, uint16_t size, uint8_t revision,
				    const char *name)
{
	memset(match, 0, sizeof(*match));
	snprintf(match->u.user.name, sizeof(match->u.user.name), "%s", name);
	match->u.user.match_size = size;
	match->u.user.revision = revision;
}

static inline void init_standard_target(struct xt_standard_target *ipt_target, int revision,
					int verdict)
{
	snprintf(ipt_target->target.u.user.name, sizeof(ipt_target->target.u.user.name), "%s",
		 BPFILTER_STANDARD_TARGET);
	ipt_target->target.u.user.revision = revision;
	ipt_target->target.u.user.target_size = sizeof(*ipt_target);
	ipt_target->verdict = verdict;
}

static inline void init_error_target(struct xt_error_target *ipt_target, int revision,
				     const char *error_name)
{
	snprintf(ipt_target->target.u.user.name, sizeof(ipt_target->target.u.user.name), "%s",
		 BPFILTER_ERROR_TARGET);
	ipt_target->target.u.user.revision = revision;
	ipt_target->target.u.user.target_size = sizeof(*ipt_target);
	snprintf(ipt_target->errorname, sizeof(ipt_target->errorname), "%s", error_name);
}

#endif // BPFILTER_UTIL_H
