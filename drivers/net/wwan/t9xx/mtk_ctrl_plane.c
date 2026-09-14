// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 * Copyright (c) 2022-2023, Intel Corporation.
 */

#include <linux/device.h>

#include "mtk_ctrl_plane.h"
#include "mtk_port.h"

/**
 * mtk_ctrl_init() - Initialize the control plane block.
 * @mdev: Pointer to the MTK modem device.
 * @ops: HIF operations for the control plane.
 * @cfg: Control plane configuration.
 *
 * Allocates and initializes the control plane block
 * associated with @mdev.
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_ctrl_init(struct mtk_md_dev *mdev, struct mtk_ctrl_hif_ops *ops, struct mtk_ctrl_cfg *cfg)
{
	struct mtk_ctrl_blk *ctrl_blk;
	int err;

	ctrl_blk = devm_kzalloc(mdev->dev, sizeof(*ctrl_blk), GFP_KERNEL);
	if (!ctrl_blk)
		return -ENOMEM;

	ctrl_blk->mdev = mdev;
	mdev->ctrl_blk = ctrl_blk;
	ctrl_blk->ops = ops;

	err = mtk_port_mngr_init(ctrl_blk, cfg->port_layer_cfg->port_cfg,
				 cfg->port_layer_cfg->port_cnt);
	if (err)
		goto err_free_mem;

	return 0;

err_free_mem:
	return err;
}
EXPORT_SYMBOL_GPL(mtk_ctrl_init);

/**
 * mtk_ctrl_exit() - Clean up the control plane block.
 * @mdev: Pointer to the MTK modem device.
 *
 * Clears the control plane block pointer. The allocation
 * itself is managed by devres and freed on driver detach.
 */
void mtk_ctrl_exit(struct mtk_md_dev *mdev)
{
	struct mtk_ctrl_blk *ctrl_blk = mdev->ctrl_blk;

	mtk_port_mngr_exit(ctrl_blk);
	mdev->ctrl_blk = NULL;
}
EXPORT_SYMBOL_GPL(mtk_ctrl_exit);
