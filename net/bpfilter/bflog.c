// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "bflog.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "context.h"

void bflog(struct context *ctx, int level, const char *fmt, ...)
{
	if (ctx->log_file &&
	    (level == BFLOG_LEVEL_FATAL || (level & ctx->log_level))) {
		va_list va;

		va_start(va, fmt);
		vfprintf(ctx->log_file, fmt, va);
		va_end(va);
	}

	if (level == BFLOG_LEVEL_FATAL)
		exit(EXIT_FAILURE);
}
