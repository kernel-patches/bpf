/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_RULE_H
#define NET_BPFILTER_RULE_H

#include <stdint.h>

#include "target.h"

struct bpfilter_ipt_entry;
struct context;
struct match;

struct rule {
	uint32_t offset;
	uint16_t num_matches;
	struct match *matches;
	struct target target;
};

int init_rule(struct context *ctx, const struct bpfilter_ipt_entry *ipt_entry, struct rule *rule);
void free_rule(struct rule *rule);

#endif // NET_BPFILTER_RULE_H
