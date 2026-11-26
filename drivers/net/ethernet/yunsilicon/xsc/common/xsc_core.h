/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_CORE_H
#define __XSC_CORE_H

#include <linux/pci.h>
#include <linux/bitfield.h>

#define XSC_PCI_VENDOR_ID		0x1f67

#define XSC_MC_PF_DEV_ID		0x1011

#define XSC_MF_HOST_PF_DEV_ID		0x1051
#define XSC_MF_SOC_PF_DEV_ID		0x1053

#define XSC_MS_PF_DEV_ID		0x1111

#define XSC_MV_HOST_PF_DEV_ID		0x1151
#define XSC_MV_SOC_PF_DEV_ID		0x1153

#define XSC_PAGE_SHIFT_4K		12
#define XSC_PAGE_SIZE_4K		(_AC(1, UL) << XSC_PAGE_SHIFT_4K)

struct xsc_core_device {
	struct pci_dev		*pdev;
	struct device		*device;

	void __iomem		*bar;
	int			bar_num;
};

#endif
