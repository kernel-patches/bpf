// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "target.h"

#include <linux/err.h>
#include <linux/netfilter/x_tables.h>

#include <errno.h>
#include <string.h>

#include "context.h"
#include "map-common.h"

static const struct target_ops *target_ops_map_find(struct hsearch_data *map, const char *name)
{
	const size_t namelen = strnlen(name, BPFILTER_EXTENSION_MAXNAMELEN);

	if (namelen < BPFILTER_EXTENSION_MAXNAMELEN)
		return map_find(map, name);

	return ERR_PTR(-EINVAL);
}

static int standard_target_check(struct context *ctx, const struct bpfilter_ipt_target *ipt_target)
{
	const struct bpfilter_ipt_standard_target *standard_target;

	standard_target = (const struct bpfilter_ipt_standard_target *)ipt_target;

	// Positive values of verdict denote a jump offset into a blob.
	if (standard_target->verdict > 0)
		return 0;

	// Special values like ACCEPT, DROP, RETURN are encoded as negative values.
	if (standard_target->verdict < 0) {
		if (standard_target->verdict == BPFILTER_RETURN)
			return 0;

		switch (convert_verdict(standard_target->verdict)) {
		case BPFILTER_NF_ACCEPT:
		case BPFILTER_NF_DROP:
		case BPFILTER_NF_QUEUE:
			return 0;
		}
	}

	BFLOG_DEBUG(ctx, "invalid verdict: %d\n", standard_target->verdict);

	return -EINVAL;
}

const struct target_ops standard_target_ops = {
	.name = "",
	.revision = 0,
	.size = sizeof(struct xt_standard_target),
	.check = standard_target_check,
};

static int error_target_check(struct context *ctx, const struct bpfilter_ipt_target *ipt_target)
{
	const struct bpfilter_ipt_error_target *error_target;
	size_t maxlen;

	error_target = (const struct bpfilter_ipt_error_target *)&ipt_target;
	maxlen = sizeof(error_target->error_name);
	if (strnlen(error_target->error_name, maxlen) == maxlen) {
		BFLOG_DEBUG(ctx, "cannot check error target: too long errorname\n");
		return -EINVAL;
	}

	return 0;
}

const struct target_ops error_target_ops = {
	.name = "ERROR",
	.revision = 0,
	.size = sizeof(struct xt_error_target),
	.check = error_target_check,
};

int init_target(struct context *ctx, const struct bpfilter_ipt_target *ipt_target,
		struct target *target)
{
	const size_t maxlen = sizeof(ipt_target->u.user.name);
	const struct target_ops *found;
	int err;

	if (strnlen(ipt_target->u.user.name, maxlen) == maxlen) {
		BFLOG_DEBUG(ctx, "cannot init target: too long target name\n");
		return -EINVAL;
	}

	found = target_ops_map_find(&ctx->target_ops_map, ipt_target->u.user.name);
	if (IS_ERR(found)) {
		BFLOG_DEBUG(ctx, "cannot find target by name: '%s'\n", ipt_target->u.user.name);
		return PTR_ERR(found);
	}

	if (found->size != ipt_target->u.target_size ||
	    found->revision != ipt_target->u.user.revision) {
		BFLOG_DEBUG(ctx, "invalid target: '%s'\n", ipt_target->u.user.name);
		return -EINVAL;
	}

	err = found->check(ctx, ipt_target);
	if (err)
		return err;

	target->target_ops = found;
	target->ipt_target = ipt_target;

	return 0;
}
