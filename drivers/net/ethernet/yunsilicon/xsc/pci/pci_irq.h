/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_PCI_IRQ_H
#define __XSC_PCI_IRQ_H

#include "common/xsc_core.h"

int xsc_irq_eq_create(struct xsc_core_device *xdev);
void xsc_irq_eq_destroy(struct xsc_core_device *xdev);
int xsc_core_vector2eqn(struct xsc_core_device *xdev, int vector, u32 *eqn,
			unsigned int *irqn);

#endif
