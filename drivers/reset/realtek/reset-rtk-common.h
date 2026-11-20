/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Realtek Semiconductor Corporation
 * Author: Yu-Chun Lin <eleanor.lin@realtek.com>
 */

#ifndef __RESET_REALTEK_COMMON_H
#define __RESET_REALTEK_COMMON_H

#include <linux/reset-controller.h>
#include <linux/types.h>

struct regmap;

struct rtk_reset_desc {
	u32 ofs;
	u32 bit;
	bool write_en;
};

struct rtk_reset_data {
	struct reset_controller_dev rcdev;
	const struct rtk_reset_desc *descs;
	struct regmap *regmap;
};

extern const struct reset_control_ops rtk_reset_ops;

#endif /* __RESET_REALTEK_COMMON_H */
