// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>

#include <errno.h>

#include "context.h"
#include "match.h"

static int xt_udp_check(struct context *ctx, const struct bpfilter_ipt_match *ipt_match)
{
	const struct xt_udp *udp;

	udp = (const struct xt_udp *)&ipt_match->data;

	if (udp->invflags & XT_UDP_INV_MASK) {
		BFLOG_DEBUG(ctx, "cannot check match 'udp': invalid flags\n");
		return -EINVAL;
	}

	return 0;
}

const struct match_ops xt_udp = { .name = "udp",
				  .size = XT_ALIGN(sizeof(struct xt_udp)),
				  .revision = 0,
				  .check = xt_udp_check };
