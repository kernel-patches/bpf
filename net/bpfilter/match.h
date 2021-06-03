/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_MATCH_H
#define NET_BPFILTER_MATCH_H

#include "../../include/uapi/linux/bpfilter.h"

#include <stdint.h>

struct bpfilter_ipt_match;
struct context;

struct match_ops {
	char name[BPFILTER_EXTENSION_MAXNAMELEN];
	uint8_t revision;
	uint16_t size;
	int (*check)(struct context *ctx, const struct bpfilter_ipt_match *ipt_match);
};

struct match {
	const struct match_ops *match_ops;
	const struct bpfilter_ipt_match *ipt_match;
};

extern const struct match_ops xt_udp;

int init_match(struct context *ctx, const struct bpfilter_ipt_match *ipt_match,
	       struct match *match);

#endif // NET_BPFILTER_MATCH_H
