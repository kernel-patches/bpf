/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_CONTEXT_H
#define NET_BPFILTER_CONTEXT_H

struct context {
};

int create_context(struct context *ctx);
void free_context(struct context *ctx);

#endif // NET_BPFILTER_CONTEXT_H
