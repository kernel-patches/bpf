/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_TRANS_CTRL_H__
#define __MTK_TRANS_CTRL_H__

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "mtk_dev.h"

struct mtk_ctrl_trans {
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_md_dev *mdev;
};

#endif
