// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>

#include "bflog.h"
#include "context.h"
#include "io.h"
#include "msgfmt.h"
#include "sockopt.h"

static int setup_context(struct context *ctx)
{
	ctx->log_file = fopen("/dev/kmsg", "w");
	if (!ctx->log_file)
		return -errno;

	setvbuf(ctx->log_file, 0, _IOLBF, 0);
	ctx->log_level = BFLOG_LEVEL_NOTICE;

	return 0;
}

static void loop(struct context *ctx)
{
	struct mbox_request req;
	struct mbox_reply reply;
	int err;

	for (;;) {
		err = read_exact(STDIN_FILENO, &req, sizeof(req));
		if (err)
			BFLOG_FATAL(ctx, "cannot read request: %s\n", strerror(-err));

		reply.status = handle_sockopt_request(ctx, &req);

		err = write_exact(STDOUT_FILENO, &reply, sizeof(reply));
		if (err)
			BFLOG_FATAL(ctx, "cannot write reply: %s\n", strerror(-err));
	}
}

int main(void)
{
	struct context ctx;
	int err;

	err = create_context(&ctx);
	if (err)
		return err;

	err = setup_context(&ctx);
	if (err) {
		free_context(&ctx);
		return err;
	}

	BFLOG_NOTICE(&ctx, "started\n");

	loop(&ctx);

	return 0;
}
