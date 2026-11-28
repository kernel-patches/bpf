/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_QP_H
#define __XSC_QP_H

#include "common/xsc_core.h"

void xsc_init_qp_table(struct xsc_core_device *xdev);
void xsc_qp_event(struct xsc_core_device *xdev, u32 qpn, int event_type);

#endif /* __XSC_QP_H */
