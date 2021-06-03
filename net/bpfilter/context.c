// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "context.h"

#include <linux/err.h>
#include <linux/list.h>

#include <string.h>

#include "map-common.h"
#include "match.h"
#include "rule.h"
#include "table.h"
#include "target.h"

static int init_match_ops_map(struct context *ctx)
{
	const struct match_ops *match_ops[] = { &xt_udp };
	int i, err;

	err = create_map(&ctx->match_ops_map, ARRAY_SIZE(match_ops));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(match_ops); ++i) {
		const struct match_ops *m = match_ops[i];

		err = map_insert(&ctx->match_ops_map, m->name, (void *)m);
		if (err)
			return err;
	}

	return 0;
}

static int init_target_ops_map(struct context *ctx)
{
	const struct target_ops *target_ops[] = { &standard_target_ops, &error_target_ops };
	int i, err;

	err = create_map(&ctx->target_ops_map, ARRAY_SIZE(target_ops));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(target_ops); ++i) {
		const struct target_ops *t = target_ops[i];

		err = map_insert(&ctx->target_ops_map, t->name, (void *)t);
		if (err)
			return err;
	}

	return 0;
}

static void init_standard_entry(struct bpfilter_ipt_standard_entry *ipt_entry)
{
	ipt_entry->entry.next_offset = sizeof(*ipt_entry);
	ipt_entry->entry.target_offset = sizeof(ipt_entry->entry);
	ipt_entry->target.target.u.user.revision = 0;
	ipt_entry->target.target.u.user.target_size = sizeof(struct bpfilter_ipt_standard_target);
	ipt_entry->target.verdict = -BPFILTER_NF_ACCEPT - 1;
}

static void init_error_entry(struct bpfilter_ipt_error_entry *ipt_entry)
{
	ipt_entry->entry.next_offset = sizeof(*ipt_entry);
	ipt_entry->entry.target_offset = sizeof(ipt_entry->entry);
	ipt_entry->target.target.u.target_size = sizeof(struct bpfilter_ipt_error_target);
	ipt_entry->target.target.u.user.revision = 0;
	snprintf(ipt_entry->target.target.u.user.name, sizeof(ipt_entry->target.target.u.user.name),
		 "ERROR");
}

static struct table *create_filter_table(struct context *ctx)
{
	struct filter_table_entries {
		struct bpfilter_ipt_standard_entry local_in;
		struct bpfilter_ipt_standard_entry forward;
		struct bpfilter_ipt_standard_entry local_out;
		struct bpfilter_ipt_error_entry error;
	};

	struct filter_table {
		struct bpfilter_ipt_replace replace;
		struct filter_table_entries entries;
	} filter_table;

	memset(&filter_table, 0, sizeof(filter_table));

	snprintf(filter_table.replace.name, sizeof(filter_table.replace.name), "filter");
	filter_table.replace.valid_hooks = 1 << BPFILTER_INET_HOOK_LOCAL_IN |
					   1 << BPFILTER_INET_HOOK_FORWARD |
					   1 << BPFILTER_INET_HOOK_LOCAL_OUT;
	filter_table.replace.num_entries = 4;
	filter_table.replace.size = sizeof(struct filter_table_entries);

	filter_table.replace.hook_entry[BPFILTER_INET_HOOK_FORWARD] =
		offsetof(struct filter_table_entries, forward);
	filter_table.replace.underflow[BPFILTER_INET_HOOK_FORWARD] =
		offsetof(struct filter_table_entries, forward);

	filter_table.replace.hook_entry[BPFILTER_INET_HOOK_LOCAL_OUT] =
		offsetof(struct filter_table_entries, local_out);
	filter_table.replace.underflow[BPFILTER_INET_HOOK_LOCAL_OUT] =
		offsetof(struct filter_table_entries, local_out);

	init_standard_entry(&filter_table.entries.local_in);
	init_standard_entry(&filter_table.entries.forward);
	init_standard_entry(&filter_table.entries.local_out);
	init_error_entry(&filter_table.entries.error);

	return create_table(ctx, &filter_table.replace);
}

static int init_table_index(struct context *ctx)
{
	struct table *table;
	int err;

	INIT_LIST_HEAD(&ctx->table_index.list);

	err = create_map(&ctx->table_index.map, 1);
	if (err)
		return err;

	table = create_filter_table(ctx);
	if (IS_ERR(table)) {
		free_map(&ctx->table_index.map);
		return PTR_ERR(table);
	}

	list_add_tail(&table->list, &ctx->table_index.list);

	return map_insert(&ctx->table_index.map, table->name, table);
}

int create_context(struct context *ctx)
{
	int err;

	err = init_match_ops_map(ctx);
	if (err)
		return err;

	err = init_target_ops_map(ctx);
	if (err) {
		free_map(&ctx->match_ops_map);
		return err;
	}

	err = init_table_index(ctx);
	if (err) {
		free_map(&ctx->match_ops_map);
		free_map(&ctx->target_ops_map);
		return err;
	}

	return 0;
}

void free_context(struct context *ctx)
{
	struct list_head *t, *n;

	list_for_each_safe(t, n, &ctx->table_index.list) {
		struct table *table;

		table = list_entry(t, struct table, list);
		free_table(table);
	}

	free_map(&ctx->table_index.map);
	free_map(&ctx->match_ops_map);
	free_map(&ctx->target_ops_map);
}
