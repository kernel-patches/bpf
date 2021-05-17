// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "match.h"

#include <linux/err.h>
#include <linux/netfilter/xt_tcpudp.h>

#include <errno.h>
#include <string.h>

#include "bflog.h"
#include "context.h"
#include "match-ops-map.h"

#define BPFILTER_ALIGN(__X) __ALIGN_KERNEL(__X, __alignof__(__u64))
#define MATCH_SIZE(type) (sizeof(struct bpfilter_ipt_match) + BPFILTER_ALIGN(sizeof(type)))

static int udp_match_check(struct context *ctx, const struct bpfilter_ipt_match *ipt_match)
{
	const struct xt_udp *udp;

	udp = (const struct xt_udp *)&ipt_match->data;

	if (udp->invflags & XT_UDP_INV_MASK) {
		BFLOG_DEBUG(ctx, "cannot check match 'udp': invalid flags\n");
		return -EINVAL;
	}

	return 0;
}

const struct match_ops udp_match_ops = { .name = "udp",
					 .size = MATCH_SIZE(struct xt_udp),
					 .revision = 0,
					 .check = udp_match_check };

int init_match(struct context *ctx, const struct bpfilter_ipt_match *ipt_match, struct match *match)
{
	const size_t maxlen = sizeof(ipt_match->u.user.name);
	const struct match_ops *found;
	int err;

	if (strnlen(ipt_match->u.user.name, maxlen) == maxlen) {
		BFLOG_DEBUG(ctx, "cannot init match: too long match name\n");
		return -EINVAL;
	}

	found = match_ops_map_find(&ctx->match_ops_map, ipt_match->u.user.name);
	if (IS_ERR(found)) {
		BFLOG_DEBUG(ctx, "cannot find match by name: '%s'\n", ipt_match->u.user.name);
		return PTR_ERR(found);
	}

	if (found->size != ipt_match->u.match_size ||
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
