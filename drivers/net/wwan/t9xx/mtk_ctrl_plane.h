/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_CTRL_PLANE_H__
#define __MTK_CTRL_PLANE_H__

#include <linux/kref.h>
#include <linux/skbuff.h>

#include "mtk_dev.h"

struct mtk_ctrl_blk {
	struct mtk_md_dev *mdev;
	struct mtk_ctrl_trans *trans;
};

int mtk_ctrl_init(struct mtk_md_dev *mdev);
void mtk_ctrl_exit(struct mtk_md_dev *mdev);

#endif /* __MTK_CTRL_PLANE_H__ */
