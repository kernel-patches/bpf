// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/pci.h>
#include "nbl_dispatch.h"

static void nbl_disp_deinit_module(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;

	if (res_ops->deinit_module)
		res_ops->deinit_module(p);
}

static int nbl_disp_init_module(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;

	if (res_ops->init_module)
		return res_ops->init_module(p);
	return -EOPNOTSUPP;
}

static void nbl_disp_set_ctrl_bit(struct nbl_dispatch_mgt *disp_mgt, u32 lvl)
{
	set_bit(lvl, disp_mgt->ctrl_lvl);
}

static void nbl_disp_refresh_ctrl_ops(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_dispatch_ops *disp_ops = disp_mgt->disp_ops_tbl->ops;

	if (test_bit(NBL_DISP_CTRL_LVL_MGT, disp_mgt->ctrl_lvl)) {
		disp_ops->init_module = nbl_disp_init_module;
		disp_ops->deinit_module = nbl_disp_deinit_module;
	}
}

static struct nbl_dispatch_mgt *
nbl_disp_setup_disp_mgt(struct nbl_common_info *common)
{
	struct nbl_dispatch_mgt *disp_mgt;
	struct device *dev = common->dev;

	disp_mgt = devm_kzalloc(dev, sizeof(*disp_mgt), GFP_KERNEL);
	if (!disp_mgt)
		return ERR_PTR(-ENOMEM);

	disp_mgt->common = common;
	return disp_mgt;
}

static struct nbl_dispatch_ops_tbl *
nbl_disp_setup_ops(struct device *dev, struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops_tbl = devm_kzalloc(dev, sizeof(*disp_ops_tbl), GFP_KERNEL);
	if (!disp_ops_tbl)
		return ERR_PTR(-ENOMEM);

	disp_ops = devm_kzalloc(dev, sizeof(*disp_ops), GFP_KERNEL);
	if (!disp_ops)
		return ERR_PTR(-ENOMEM);

	disp_ops_tbl->ops = disp_ops;
	disp_ops_tbl->priv = disp_mgt;

	return disp_ops_tbl;
}

int nbl_disp_init(struct nbl_adapter *adapter)
{
	struct nbl_common_info *common = &adapter->common;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_resource_ops_tbl *res_ops_tbl =
		adapter->intf.resource_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl =
		adapter->intf.channel_ops_tbl;
	struct device *dev = &adapter->pdev->dev;
	struct nbl_dispatch_mgt *disp_mgt;
	int ret;

	disp_mgt = nbl_disp_setup_disp_mgt(common);
	if (IS_ERR(disp_mgt)) {
		ret = PTR_ERR(disp_mgt);
		return ret;
	}

	disp_ops_tbl = nbl_disp_setup_ops(dev, disp_mgt);
	if (IS_ERR(disp_ops_tbl)) {
		ret = PTR_ERR(disp_ops_tbl);
		return ret;
	}

	disp_mgt->res_ops_tbl = res_ops_tbl;
	disp_mgt->chan_ops_tbl = chan_ops_tbl;
	disp_mgt->disp_ops_tbl = disp_ops_tbl;
	adapter->core.disp_mgt = disp_mgt;
	adapter->intf.dispatch_ops_tbl = disp_ops_tbl;

	if (common->has_ctrl)
		nbl_disp_set_ctrl_bit(disp_mgt, NBL_DISP_CTRL_LVL_MGT);

	nbl_disp_refresh_ctrl_ops(disp_mgt);
	return 0;
}

void nbl_disp_remove(struct nbl_adapter *adapter)
{
	/* Dispatch structures are allocated via devm */
}
