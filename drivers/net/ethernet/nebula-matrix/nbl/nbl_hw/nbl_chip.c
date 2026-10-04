// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include "nbl_chip.h"

void nbl_res_chip_deinit_module(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct nbl_common_info *common = res_mgt->common;

	if (!common->has_ctrl)
		return;
	hw_ops->deinit_module(res_mgt->hw_ops_tbl->priv);
}

int nbl_res_chip_init_module(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = res_mgt->common;
	struct nbl_hw_ops *hw_ops;
	u8 eth_speed, eth_num;
	struct nbl_hw_mgt *p;

	if (!common->has_ctrl)
		return -EINVAL;
	eth_speed = res_mgt->resource_info->board_info.eth_speed;
	eth_num = res_mgt->resource_info->board_info.eth_num;
	hw_ops = res_mgt->hw_ops_tbl->ops;
	p = res_mgt->hw_ops_tbl->priv;
	return hw_ops->init_module(p, eth_speed, eth_num);
}
