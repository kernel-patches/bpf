/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __EQ_H
#define __EQ_H

#include "common/xsc_core.h"

enum {
	XSC_EQ_VEC_ASYNC		= 0,
	XSC_VEC_CMD			= 1,
	XSC_VEC_CMD_EVENT		= 2,
	XSC_DMA_READ_DONE_VEC		= 3,
	XSC_EQ_VEC_COMP_BASE,
};

struct xsc_eqe {
	u8 type;
	u8 sub_type;
	__le16 queue_id_data;
#define XSC_EQE_QUEUE_ID_MASK	GENMASK(14, 0)

	u8 err_code;
	u8 rsvd[2];
	u8 owner_data;
#define XSC_EQE_OWNER		BIT(7)
};

int xsc_create_map_eq(struct xsc_core_device *xdev,
		      struct xsc_eq *eq, u16 vecidx,
		      u32 nent, const char *name);
int xsc_destroy_unmap_eq(struct xsc_core_device *xdev, struct xsc_eq *eq);
int xsc_start_eqs(struct xsc_core_device *xdev);
void xsc_stop_eqs(struct xsc_core_device *xdev);

#endif
