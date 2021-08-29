// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "context.h"

#include <linux/err.h>
#include <linux/list.h>

#include <string.h>

#include "filter-table.h"
#include "map-common.h"
#include "match.h"
#include "rule.h"
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

		err = map_upsert(&ctx->match_ops_map, m->name, (void *)m);
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

		err = map_upsert(&ctx->target_ops_map, t->name, (void *)t);
		if (err)
			return err;
	}

	return 0;
}

static const struct table_ops *table_ops[] = { &filter_table_ops };

static int init_table_ops_map(struct context *ctx)
{
	int i, err;

	err = create_map(&ctx->table_ops_map, ARRAY_SIZE(table_ops));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(table_ops); ++i) {
		const struct table_ops *t = table_ops[i];

		err = map_upsert(&ctx->table_ops_map, t->name, (void *)t);
		if (err)
			return err;
	}

	return 0;
}

static int init_table_index(struct context *ctx)
{
	INIT_LIST_HEAD(&ctx->table_index.list);

	return create_map(&ctx->table_index.map, ARRAY_SIZE(table_ops));
}

int create_context(struct context *ctx)
{
	int err;

	err = init_match_ops_map(ctx);
	if (err)
		return err;

	err = init_target_ops_map(ctx);
	if (err)
		goto err_free_match_ops_map;

	err = init_table_ops_map(ctx);
	if (err)
		goto err_free_target_ops_map;

	err = init_table_index(ctx);
	if (err)
		goto err_free_table_ops_map;

	return 0;

err_free_table_ops_map:
	free_map(&ctx->table_ops_map);

err_free_target_ops_map:
	free_map(&ctx->target_ops_map);

err_free_match_ops_map:
	free_map(&ctx->match_ops_map);

	return err;
}

void free_context(struct context *ctx)
{
	struct list_head *t, *n;

	list_for_each_safe(t, n, &ctx->table_index.list) {
		struct table *table;

		table = list_entry(t, struct table, list);
		table->table_ops->uninstall(ctx, table);
		table->table_ops->free(table);
	}
	free_map(&ctx->table_index.map);
	free_map(&ctx->table_ops_map);
	free_map(&ctx->target_ops_map);
	free_map(&ctx->match_ops_map);
}
