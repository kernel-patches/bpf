// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "match.h"

#include <linux/err.h>

#include <errno.h>
#include <string.h>

#include "context.h"
#include "map-common.h"

int init_match(struct context *ctx, const struct bpfilter_ipt_match *ipt_match, struct match *match)
{
	const size_t maxlen = sizeof(ipt_match->u.user.name);
	const struct match_ops *found;
	int err;

	if (strnlen(ipt_match->u.user.name, maxlen) == maxlen) {
		BFLOG_DEBUG(ctx, "cannot init match: too long match name\n");
		return -EINVAL;
	}

	found = map_find(&ctx->match_ops_map, ipt_match->u.user.name);
	if (IS_ERR(found)) {
		BFLOG_DEBUG(ctx, "cannot find match by name: '%s'\n", ipt_match->u.user.name);
		return PTR_ERR(found);
	}

	if (found->size + sizeof(*ipt_match) != ipt_match->u.match_size ||
	    found->revision != ipt_match->u.user.revision) {
		BFLOG_DEBUG(ctx, "invalid match: '%s'\n", ipt_match->u.user.name);
		return -EINVAL;
	}

	err = found->check(ctx, ipt_match);
	if (err)
		return err;

	match->match_ops = found;
	match->ipt_match = ipt_match;

	return 0;
}
