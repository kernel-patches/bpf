// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "rule.h"

#include "../../include/uapi/linux/bpfilter.h"

#include <linux/err.h>
#include <linux/netfilter/x_tables.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "match.h"

static const struct bpfilter_ipt_target *
ipt_entry_target(const struct bpfilter_ipt_entry *ipt_entry)
{
	return (const void *)ipt_entry + ipt_entry->target_offset;
}

static const struct bpfilter_ipt_match *ipt_entry_match(const struct bpfilter_ipt_entry *entry,
							size_t offset)
{
	return (const void *)entry + offset;
}

static int ipt_entry_num_matches(const struct bpfilter_ipt_entry *ipt_entry)
{
	const struct bpfilter_ipt_match *ipt_match;
	uint32_t offset = sizeof(*ipt_entry);
	int num_matches = 0;

	while (offset < ipt_entry->target_offset) {
		ipt_match = ipt_entry_match(ipt_entry, offset);

		if ((uintptr_t)ipt_match % __alignof__(struct bpfilter_ipt_match))
			return -EINVAL;

		if (ipt_entry->target_offset < offset + sizeof(*ipt_match))
			return -EINVAL;

		if (ipt_match->u.match_size < sizeof(*ipt_match))
			return -EINVAL;

		if (ipt_entry->target_offset < offset + ipt_match->u.match_size)
			return -EINVAL;

		++num_matches;
		offset += ipt_match->u.match_size;
	}

	if (offset != ipt_entry->target_offset)
		return -EINVAL;

	return num_matches;
}

static int init_rule_matches(struct context *ctx, const struct bpfilter_ipt_entry *ipt_entry,
			     struct rule *rule)
{
	const struct bpfilter_ipt_match *ipt_match;
	uint32_t offset = sizeof(*ipt_entry);
	struct match *match;
	int err;

	rule->matches = calloc(rule->num_matches, sizeof(rule->matches[0]));
	if (!rule->matches)
		return -ENOMEM;

	match = rule->matches;
	while (offset < ipt_entry->target_offset) {
		ipt_match = ipt_entry_match(ipt_entry, offset);
		err = init_match(ctx, ipt_match, match);
		if (err) {
			free(rule->matches);
			rule->matches = NULL;
			return err;
		}

		++match;
		offset += ipt_match->u.match_size;
	}

	return 0;
}

static int check_ipt_entry_ip(const struct bpfilter_ipt_ip *ip)
{
	if (ip->flags & ~BPFILTER_IPT_F_MASK)
		return -EINVAL;

	if (ip->invflags & ~BPFILTER_IPT_INV_MASK)
		return -EINVAL;

	return 0;
}

bool rule_has_standard_target(const struct rule *rule)
{
	return rule->target.target_ops == &standard_target_ops;
}

bool is_rule_unconditional(const struct rule *rule)
{
	static const struct bpfilter_ipt_ip unconditional;

	if (rule->num_matches)
		return false;

	return !memcmp(&rule->ipt_entry->ip, &unconditional, sizeof(unconditional));
}

int init_rule(struct context *ctx, const struct bpfilter_ipt_entry *ipt_entry, struct rule *rule)
{
	const struct bpfilter_ipt_target *ipt_target;
	int err;

	err = check_ipt_entry_ip(&ipt_entry->ip);
	if (err)
		return err;

	if (ipt_entry->target_offset < sizeof(*ipt_entry))
		return -EINVAL;

	if (ipt_entry->next_offset < ipt_entry->target_offset + sizeof(*ipt_target))
		return -EINVAL;

	ipt_target = ipt_entry_target(ipt_entry);

	if (ipt_target->u.target_size < sizeof(*ipt_target))
		return -EINVAL;

	if (ipt_entry->next_offset < ipt_entry->target_offset + ipt_target->u.target_size)
		return -EINVAL;

	err = init_target(ctx, ipt_target, &rule->target);
	if (err)
		return err;

	if (rule_has_standard_target(rule)) {
		if (XT_ALIGN(ipt_entry->target_offset +
			     sizeof(struct bpfilter_ipt_standard_target)) != ipt_entry->next_offset)
			return -EINVAL;
	}

	rule->num_matches = ipt_entry_num_matches(ipt_entry);
	if (rule->num_matches < 0)
		return rule->num_matches;

	return init_rule_matches(ctx, ipt_entry, rule);
}

void free_rule(struct rule *rule)
{
	free(rule->matches);
}
