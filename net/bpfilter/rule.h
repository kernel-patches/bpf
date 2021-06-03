/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_RULE_H
#define NET_BPFILTER_RULE_H

#include <stdint.h>
#include <stdbool.h>

#include "target.h"

struct bpfilter_ipt_entry;
struct context;
struct match;

struct rule {
	const struct bpfilter_ipt_entry *ipt_entry;
	uint32_t came_from;
	uint32_t hook_mask;
	uint16_t num_matches;
	struct match *matches;
	struct target target;
};

bool rule_has_standard_target(const struct rule *rule);
bool is_rule_unconditional(const struct rule *rule);
int init_rule(struct context *ctx, const struct bpfilter_ipt_entry *ipt_entry, struct rule *rule);
void free_rule(struct rule *rule);

#endif // NET_BPFILTER_RULE_H
