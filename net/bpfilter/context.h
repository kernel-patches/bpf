/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_CONTEXT_H
#define NET_BPFILTER_CONTEXT_H

#include <stdio.h>

#include "match-ops-map.h"

struct context {
	FILE *log_file;
	int log_level;
	struct match_ops_map match_ops_map;
};

int create_context(struct context *ctx);
void free_context(struct context *ctx);

#endif // NET_BPFILTER_CONTEXT_H
