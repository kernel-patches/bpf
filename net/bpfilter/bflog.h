/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_BFLOG_H
#define NET_BPFILTER_BFLOG_H

struct context;

#define BFLOG_IMPL(ctx, level, fmt, ...) bflog(ctx, level, "bpfilter: " fmt, ##__VA_ARGS__)

#define BFLOG_LEVEL_FATAL (0)
#define BFLOG_LEVEL_NOTICE (1)
#define BFLOG_LEVEL_DEBUG (2)

#define BFLOG_FATAL(ctx, fmt, ...)                                                                 \
	BFLOG_IMPL(ctx, BFLOG_LEVEL_FATAL, "fatal error: " fmt, ##__VA_ARGS__)
#define BFLOG_NOTICE(ctx, fmt, ...) BFLOG_IMPL(ctx, BFLOG_LEVEL_NOTICE, fmt, ##__VA_ARGS__)
#define BFLOG_DEBUG(ctx, fmt, ...) BFLOG_IMPL(ctx, BFLOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

void bflog(struct context *ctx, int level, const char *fmt, ...);

#endif // NET_BPFILTER_BFLOG_H
