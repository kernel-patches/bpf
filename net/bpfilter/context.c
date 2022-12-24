// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include "context.h"

#include <linux/kernel.h>

#include <string.h>

#include "logger.h"
#include "map-common.h"
#include "match.h"

static const struct match_ops *match_ops[] = { };

static int init_match_ops_map(struct context *ctx)
{
	int r;

	r = create_map(&ctx->match_ops_map, ARRAY_SIZE(match_ops));
	if (r) {
		BFLOG_ERR("failed to create matches map: %s", STRERR(r));
		return r;
	}

	for (int i = 0; i < ARRAY_SIZE(match_ops); ++i) {
		const struct match_ops *m = match_ops[i];

		r = map_upsert(&ctx->match_ops_map, m->name, (void *)m);
		if (r) {
			BFLOG_ERR("failed to upsert in matches map: %s",
				  STRERR(r));
			return r;
		}
	}

	return 0;
}

int create_context(struct context *ctx)
{
	int r;

	r = init_match_ops_map(ctx);
	if (r) {
		BFLOG_ERR("failed to initialize matches map: %s", STRERR(r));
		return r;
	}

	return 0;
}

void free_context(struct context *ctx)
{
	free_map(&ctx->match_ops_map);
}
