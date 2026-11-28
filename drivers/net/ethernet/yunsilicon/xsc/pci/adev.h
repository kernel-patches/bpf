/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ADEV_H
#define __XSC_ADEV_H

#include "common/xsc_core.h"

int xsc_adev_init(struct xsc_core_device *xdev);
void xsc_adev_uninit(struct xsc_core_device *xdev);

#endif
