/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_TABLE_H
#define NET_BPFILTER_TABLE_H

#include "../../include/uapi/linux/bpfilter.h"

#include <stdint.h>

struct context;
struct rule;

struct table {
	struct list_head list;
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	uint32_t valid_hooks;
	uint32_t num_rules;
	uint32_t num_counters;
	uint32_t size;
	struct rule *hook_entry[BPFILTER_INET_HOOK_MAX];
	struct rule *underflow[BPFILTER_INET_HOOK_MAX];
	struct rule *rules;
	void *entries;
};

struct table *create_table(struct context *ctx, const struct bpfilter_ipt_replace *ipt_replace);
void table_get_info(const struct table *table, struct bpfilter_ipt_get_info *info);
void free_table(struct table *table);

#endif // NET_BPFILTER_TABLE_H
