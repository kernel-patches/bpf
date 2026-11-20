// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019-2026 Realtek Semiconductor Corporation
 */

#include <linux/export.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include "reset-rtk-common.h"

static inline struct rtk_reset_data *to_rtk_reset_controller(struct reset_controller_dev *r)
{
	return container_of(r, struct rtk_reset_data, rcdev);
}

static inline const struct rtk_reset_desc *rtk_reset_get_desc(struct rtk_reset_data *data,
							      unsigned long idx)
{
	return &data->descs[idx];
}

static int rtk_reset_assert(struct reset_controller_dev *rcdev,
			    unsigned long idx)
{
	struct rtk_reset_data *data = to_rtk_reset_controller(rcdev);
	const struct rtk_reset_desc *desc;
	unsigned int mask, val;

	desc = rtk_reset_get_desc(data, idx);
	mask = desc->write_en ? (0x3U << desc->bit) : BIT(desc->bit);
	val  = desc->write_en ? (0x2U << desc->bit) : 0;

	return regmap_update_bits(data->regmap, desc->ofs, mask, val);
}

static int rtk_reset_deassert(struct reset_controller_dev *rcdev,
			      unsigned long idx)
{
	struct rtk_reset_data *data = to_rtk_reset_controller(rcdev);
	const struct rtk_reset_desc *desc;
	unsigned int mask;

	desc = rtk_reset_get_desc(data, idx);
	mask = desc->write_en ? (0x3U << desc->bit) : BIT(desc->bit);

	return regmap_set_bits(data->regmap, desc->ofs, mask);
}

static int rtk_reset_status(struct reset_controller_dev *rcdev,
			    unsigned long idx)
{
	struct rtk_reset_data *data = to_rtk_reset_controller(rcdev);
	const struct rtk_reset_desc *desc;
	unsigned int val;
	int ret;

	desc = rtk_reset_get_desc(data, idx);
	ret = regmap_read(data->regmap, desc->ofs, &val);
	if (ret)
		return ret;

	return !((val >> desc->bit) & 1);
}

const struct reset_control_ops rtk_reset_ops = {
	.assert   = rtk_reset_assert,
	.deassert = rtk_reset_deassert,
	.status   = rtk_reset_status,
};
EXPORT_SYMBOL_NS_GPL(rtk_reset_ops, "REALTEK_RESET");

MODULE_DESCRIPTION("realtek reset infrastructure");
MODULE_LICENSE("GPL");
