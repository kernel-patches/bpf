/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_TARGET_H
#define NET_BPFILTER_TARGET_H

#include "../../include/uapi/linux/bpfilter.h"

#include <stdint.h>

struct context;
struct target_ops_map;

struct target_ops {
	char name[BPFILTER_EXTENSION_MAXNAMELEN];
	uint16_t size;
	uint8_t revision;
	int (*check)(struct context *ctx, const struct bpfilter_ipt_target *ipt_target);
};

struct target {
	const struct target_ops *target_ops;
	const struct bpfilter_ipt_target *ipt_target;
};

extern const struct target_ops standard_target_ops;
extern const struct target_ops error_target_ops;

int init_target(struct context *ctx, const struct bpfilter_ipt_target *ipt_target,
		struct target *target);

#endif // NET_BPFILTER_TARGET_H
