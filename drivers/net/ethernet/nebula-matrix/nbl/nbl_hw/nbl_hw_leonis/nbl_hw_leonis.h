/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_HW_LEONIS_H_
#define _NBL_HW_LEONIS_H_

#include <linux/types.h>

#include "../../nbl_include/nbl_include.h"
#include "../nbl_hw_reg.h"

/*  ----------  REG BASE ADDR  ----------  */
/* Interface modules base addr */
#define NBL_INTF_HOST_PCOMPLETER_BASE		0x00f08000
#define NBL_INTF_HOST_PADPT_BASE		0x00f4c000
#define NBL_INTF_HOST_MAILBOX_BASE		0x00fb0000
#define NBL_INTF_HOST_PCIE_BASE			0X01504000
/*  --------  MAILBOX BAR2 -----  */
#define NBL_MAILBOX_NOTIFY_ADDR			0x00000000
#define NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR	0x10
#define NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR	0x20

/*  --------  MAILBOX  --------  */

/* mailbox BAR qinfo_cfg_table */
#define MAILBOX_QINFO_CFG_TABLE_DWLEN	4
/* data[2] */
#define NBL_MAILBOX_QINFO_CFG_QUEUE_SIZE_BWID_MASK	GENMASK(3, 0)
/* data[3] */
#define NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK		BIT(0)
#define NBL_MAILBOX_QINFO_CFG_QUEUE_EN_MASK		BIT(1)
#define NBL_MAILBOX_QINFO_CFG_DIF_ERR_MASK		BIT(2)
#define NBL_MAILBOX_QINFO_CFG_PTR_ERR_MASK		BIT(3)
struct nbl_mailbox_qinfo_cfg_table {
	u32 data[MAILBOX_QINFO_CFG_TABLE_DWLEN];
};

/*  --------  MAILBOX BAR0 -----  */
/* mailbox qinfo_map_table */
#define NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id) \
	(NBL_INTF_HOST_MAILBOX_BASE + 0x00001000 + (func_id) * sizeof(u32))

/* MAILBOX qinfo_map_table */
#define NBL_MAILBOX_QINFO_MAP_FUNCTION_MASK		GENMASK(2, 0)
#define NBL_MAILBOX_QINFO_MAP_DEVID_MASK		GENMASK(7, 3)
#define NBL_MAILBOX_QINFO_MAP_BUS_MASK			GENMASK(15, 8)
#define NBL_MAILBOX_QINFO_MAP_MSIX_IDX_MASK		GENMASK(28, 16)
#define NBL_MAILBOX_QINFO_MAP_MSIX_IDX_VALID_MASK	BIT(29)

/*  --------  HOST_PCIE  --------  */
#define NBL_PCIE_HOST_K_PF_MASK_REG (NBL_INTF_HOST_PCIE_BASE + 0x00001004)
#define NBL_PCIE_HOST_TL_CFG_BUSDEV (NBL_INTF_HOST_PCIE_BASE + 0x11040)

#define NBL_BAR2_MAX_LEN		0x300
#endif
