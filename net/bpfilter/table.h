/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_TABLE_H
#define NET_BPFILTER_TABLE_H

#include "../../include/uapi/linux/bpfilter.h"

#include <search.h>
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
	uint32_t hook_entry[BPFILTER_INET_HOOK_MAX];
	uint32_t underflow[BPFILTER_INET_HOOK_MAX];
	struct rule *rules;
	void *entries;
};

struct table_index {
	struct hsearch_data map;
	struct list_head list;
};

struct table *create_table(struct context *ctx, const struct bpfilter_ipt_replace *ipt_replace);
void table_get_info(const struct table *table, struct bpfilter_ipt_get_info *info);
void free_table(struct table *table);

#endif // NET_BPFILTER_TABLE_H
