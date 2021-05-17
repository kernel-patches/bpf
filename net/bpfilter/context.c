// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "context.h"

#include <linux/err.h>
#include <linux/list.h>

#include "match.h"

static int init_match_ops_map(struct context *ctx)
{
	const struct match_ops *match_ops[] = { &udp_match_ops };
	int i, err;

	err = create_match_ops_map(&ctx->match_ops_map, ARRAY_SIZE(match_ops));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(match_ops); ++i) {
		err = match_ops_map_insert(&ctx->match_ops_map, match_ops[i]);
		if (err)
			return err;
	}

	return 0;
}

int create_context(struct context *ctx)
{
	return init_match_ops_map(ctx);
}

void free_context(struct context *ctx)
{
	free_match_ops_map(&ctx->match_ops_map);
}
