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
	MTK_USER_CTRL,
	MTK_USER_MAX
};

enum mtk_dev_evt_h2d {
	DEV_EVT_H2D_DEVICE_RESET	= BIT(2),
};

enum mtk_dev_evt_d2h {
	DEV_EVT_D2H_BOOT_FLOW_SYNC	= BIT(4),
	DEV_EVT_D2H_ASYNC_HS_NOTIFY_SAP = BIT(5),
	DEV_EVT_D2H_ASYNC_HS_NOTIFY_MD	= BIT(6),
};

/* mtk_md_dev defines the structure of MTK modem device */
struct mtk_md_dev {
	struct device *dev;
	void *hw_priv;
	u32 hw_ver;
	char dev_str[MTK_DEV_STR_LEN];
};

#endif /* __MTK_DEV_H__ */
