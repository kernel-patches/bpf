// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "context.h"

#include <linux/err.h>
#include <linux/list.h>

#include "map-common.h"
#include "match.h"
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

	return 0;
}

void free_context(struct context *ctx)
{
	free_map(&ctx->match_ops_map);
	free_map(&ctx->target_ops_map);
}
