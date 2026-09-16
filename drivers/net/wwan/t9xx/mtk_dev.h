/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_DEV_H__
#define __MTK_DEV_H__

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define MTK_DEV_STR_LEN 16

enum mtk_user_id {
	MTK_USER_MIN,
	MTK_USER_CTRL,
	MTK_USER_DATA,
	MTK_USER_MAX
};

enum mtk_dev_evt_h2d {
	DEV_EVT_H2D_DEVICE_RESET	= BIT(2),
	DEV_EVT_H2D_MAX			= BIT(5)
};

enum mtk_dev_evt_d2h {
	DEV_EVT_D2H_BOOT_FLOW_SYNC	= BIT(4),
	DEV_EVT_D2H_ASYNC_HS_NOTIFY_SAP = BIT(5),
	DEV_EVT_D2H_ASYNC_HS_NOTIFY_MD	= BIT(6),
	DEV_EVT_D2H_MAX			= BIT(11)
};

struct mtk_md_dev;
struct mtk_ctrl_blk;

struct mtk_dev_ops {
	u32 (*get_dev_state)(struct mtk_md_dev *mdev);
	void (*ack_dev_state)(struct mtk_md_dev *mdev, u32 state);
	u32 (*get_dev_cfg)(struct mtk_md_dev *mdev);
	int (*register_dev_evt)(struct mtk_md_dev *mdev, u32 dev_evt,
				int (*evt_cb)(u32 status, void *data), void *data);
	void (*unregister_dev_evt)(struct mtk_md_dev *mdev, u32 dev_evt);
	void (*mask_dev_evt)(struct mtk_md_dev *mdev, u32 dev_evt);
	void (*unmask_dev_evt)(struct mtk_md_dev *mdev, u32 dev_evt);
	void (*clear_dev_evt)(struct mtk_md_dev *mdev, u32 dev_evt);
	int (*send_dev_evt)(struct mtk_md_dev *mdev, u32 dev_evt);
};

/* mtk_md_dev defines the structure of MTK modem device */
struct mtk_md_dev {
	struct device *dev;
	const struct mtk_dev_ops *dev_ops;
	void *hw_priv;
	u32 hw_ver;
	char dev_str[MTK_DEV_STR_LEN];
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_md_fsm *fsm;
};

static inline u32 mtk_dev_get_dev_state(struct mtk_md_dev *mdev)
{
	return mdev->dev_ops->get_dev_state(mdev);
}

static inline void mtk_dev_ack_dev_state(struct mtk_md_dev *mdev, u32 state)
{
	return mdev->dev_ops->ack_dev_state(mdev, state);
}

static inline u32 mtk_dev_get_dev_cfg(struct mtk_md_dev *mdev)
{
	return mdev->dev_ops->get_dev_cfg(mdev);
}

static inline int mtk_dev_register_dev_evt(struct mtk_md_dev *mdev, u32 dev_evt,
					   int (*evt_cb)(u32 status, void *data), void *data)
{
	return mdev->dev_ops->register_dev_evt(mdev, dev_evt, evt_cb, data);
}

static inline void mtk_dev_unregister_dev_evt(struct mtk_md_dev *mdev, u32 dev_evt)
{
	mdev->dev_ops->unregister_dev_evt(mdev, dev_evt);
}

static inline void mtk_dev_mask_dev_evt(struct mtk_md_dev *mdev, u32 dev_evt)
{
	mdev->dev_ops->mask_dev_evt(mdev, dev_evt);
}

static inline void mtk_dev_unmask_dev_evt(struct mtk_md_dev *mdev, u32 dev_evt)
{
	mdev->dev_ops->unmask_dev_evt(mdev, dev_evt);
}

static inline void mtk_dev_clear_dev_evt(struct mtk_md_dev *mdev, u32 dev_evt)
{
	mdev->dev_ops->clear_dev_evt(mdev, dev_evt);
}

static inline int mtk_dev_send_dev_evt(struct mtk_md_dev *mdev, u32 dev_evt)
{
	return mdev->dev_ops->send_dev_evt(mdev, dev_evt);
}

#endif /* __MTK_DEV_H__ */
