// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 * Copyright (c) 2022-2023, Intel Corporation.
 */

#include <linux/device.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/pm_runtime.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "mtk_ctrl_plane.h"
#include "mtk_port.h"
#include "mtk_trans_ctrl.h"

static void mtk_ctrl_trans_fsm_state_handler(struct mtk_fsm_param *param,
					     struct mtk_ctrl_blk *ctrl_blk)
{
	struct mtk_md_dev *mdev = ctrl_blk->mdev;
	int ret;

	switch (param->to) {
	case FSM_STATE_OFF:
		mtk_pcie_hif_exit(mdev);
		mtk_pcie_hif_fsm_indication(mdev, param);
		break;
	case FSM_STATE_ON:
		ret = mtk_pcie_hif_init(mdev);
		if (ret) {
			dev_err(mdev->dev, "Failed to init HIF: %d\n", ret);
			mtk_fsm_hif_err_record(mdev, MTK_FSM_HIF_USER_CTRL, ret);
			break;
		}
		fallthrough;
	default:
		mtk_pcie_hif_fsm_indication(mdev, param);
		break;
	}
}

static void mtk_ctrl_fsm_state_listener(struct mtk_fsm_param *param, void *data)
{
	struct mtk_ctrl_blk *ctrl_blk = data;

	mtk_port_mngr_fsm_state_handler(param, ctrl_blk->port_mngr);
	mtk_ctrl_trans_fsm_state_handler(param, ctrl_blk);
	mtk_port_mngr_fsm_state_handler_late(param, ctrl_blk->port_mngr);
}

/**
 * mtk_ctrl_init() - Initialize the control plane block.
 * @mdev: Pointer to the MTK modem device.
 * @port_layer_cfg: Port layer configuration.
 *
 * Allocates and initializes the control plane block
 * associated with @mdev.
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_ctrl_init(struct mtk_md_dev *mdev, struct mtk_port_layer_cfg *port_layer_cfg)
{
	struct mtk_ctrl_blk *ctrl_blk;
	int err;

	ctrl_blk = devm_kzalloc(mdev->dev, sizeof(*ctrl_blk), GFP_KERNEL);
	if (!ctrl_blk)
		return -ENOMEM;

	ctrl_blk->mdev = mdev;
	mdev->ctrl_blk = ctrl_blk;

	err = mtk_port_mngr_init(ctrl_blk, port_layer_cfg->port_cfg,
				 port_layer_cfg->port_cnt);
	if (err)
		goto err_free_mem;

	err = mtk_fsm_notifier_register(mdev, MTK_USER_CTRL, mtk_ctrl_fsm_state_listener,
					ctrl_blk, FSM_PRIO_1, false);
	if (err) {
		dev_err(mdev->dev, "Fail to register fsm notification(ret = %d)\n", err);
		goto err_port_exit;
	}

	return 0;

err_port_exit:
	mtk_port_mngr_exit(ctrl_blk);
err_free_mem:
	return err;
}

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

	mtk_fsm_notifier_unregister(mdev, MTK_USER_CTRL);
	mtk_port_mngr_exit(ctrl_blk);
	mdev->ctrl_blk = NULL;
}
