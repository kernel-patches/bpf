/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_CONTEXT_H
#define NET_BPFILTER_CONTEXT_H

#include <sys/syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <search.h>

struct context {
	FILE *log_file;
	struct hsearch_data match_ops_map;
};

#define BFLOG_IMPL(ctx, level, fmt, ...)                                                           \
	do {                                                                                       \
		if ((ctx)->log_file)								   \
			fprintf((ctx)->log_file, "<%d>bpfilter: " fmt, (level), ##__VA_ARGS__);    \
		if ((level) == LOG_EMERG)                                                          \
			exit(EXIT_FAILURE);                                                        \
	} while (0)

#define BFLOG_EMERG(ctx, fmt, ...)                                                                 \
	BFLOG_IMPL(ctx, LOG_KERN | LOG_EMERG, "fatal error: " fmt, ##__VA_ARGS__)

#define BFLOG_NOTICE(ctx, fmt, ...) BFLOG_IMPL(ctx, LOG_KERN | LOG_NOTICE, fmt, ##__VA_ARGS__)

#if 0
#define BFLOG_DEBUG(ctx, fmt, ...) BFLOG_IMPL(ctx, LOG_KERN | LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#define BFLOG_DEBUG(ctx, fmt, ...)
#endif

int create_context(struct context *ctx);
void free_context(struct context *ctx);

#endif // NET_BPFILTER_CONTEXT_H
