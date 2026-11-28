// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024 - 2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/pci.h>

#include "common/xsc_core.h"
#include "common/xsc_reg.h"

/* doorbell words */
#define XSC_TX_DB_DATA0_NEXT_PID_MASK	GENMASK(15, 0)
#define XSC_TX_DB_DATA0_QP_ID_MASK	GENMASK(30, 16)
#define XSC_RX_DB_DATA0_NEXT_PID_MASK	GENMASK(12, 0)
#define XSC_RX_DB_DATA0_QP_ID_MASK	GENMASK(27, 13)
#define XSC_CQ_DB_DATA0_NEXT_CID_MASK	GENMASK(15, 0)
#define XSC_CQ_DB_DATA0_CQ_ID_MASK	GENMASK(30, 16)
#define XSC_CQ_DB_DATA0_ARM		BIT(31)
#define XSC_EQ_DB_DATA0_NEXT_CID_MASK	GENMASK(10, 0)
#define XSC_EQ_DB_DATA0_EQ_ID_MASK	GENMASK(21, 11)
#define XSC_EQ_DB_DATA0_ARM		BIT(22)

static u32 xsc_read32(void __iomem *bar, u32 off)
{
	return readl(bar + off);
}

static void xsc_write32(void __iomem *bar, u32 off, u32 val)
{
	writel(val, bar + off);
}

void xsc_update_tx_db(struct xsc_core_device *xdev, u32 sqn, u32 next_pid)
{
	u32 db = FIELD_PREP(XSC_TX_DB_DATA0_NEXT_PID_MASK, next_pid) |
		 FIELD_PREP(XSC_TX_DB_DATA0_QP_ID_MASK, sqn);

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();

	writel(db, xdev->bar + TX_DB_FUNC_MEM_ADDR);
}
EXPORT_SYMBOL_GPL(xsc_update_tx_db);

void xsc_update_rx_db(struct xsc_core_device *xdev, u32 rqn, u32 next_pid)
{
	u32 db = FIELD_PREP(XSC_RX_DB_DATA0_NEXT_PID_MASK, next_pid) |
		 FIELD_PREP(XSC_RX_DB_DATA0_QP_ID_MASK, rqn);

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();

	writel(db, xdev->bar + RX_DB_FUNC_MEM_ADDR);
}
EXPORT_SYMBOL_GPL(xsc_update_rx_db);

void xsc_arm_cq(struct xsc_core_device *xdev, u32 cqn, u32 next_cid,
		u8 solicited)
{
	u32 db = FIELD_PREP(XSC_CQ_DB_DATA0_NEXT_CID_MASK, next_cid) |
		 FIELD_PREP(XSC_CQ_DB_DATA0_CQ_ID_MASK, cqn) |
		 FIELD_PREP(XSC_CQ_DB_DATA0_ARM, !!solicited);

	/* Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();
	writel(db, xdev->bar + DB_CQ_FUNC_MEM_ADDR);
}
EXPORT_SYMBOL_GPL(xsc_arm_cq);

void xsc_update_cq_ci(struct xsc_core_device *xdev, u32 cqn, u32 next_cid)
{
	u32 db = FIELD_PREP(XSC_CQ_DB_DATA0_NEXT_CID_MASK, next_cid) |
		 FIELD_PREP(XSC_CQ_DB_DATA0_CQ_ID_MASK, cqn);

	/* make sure val write to memory done */
	wmb();
	writel(db, xdev->bar + DB_CQ_CID_DIRECT_MEM_ADDR);
}
EXPORT_SYMBOL_GPL(xsc_update_cq_ci);

void xsc_update_eq_ci(struct xsc_core_device *xdev, u32 eqn, u32 next_cid,
		      u8 arm)
{
	u32 db = FIELD_PREP(XSC_EQ_DB_DATA0_NEXT_CID_MASK, next_cid) |
		 FIELD_PREP(XSC_EQ_DB_DATA0_EQ_ID_MASK, eqn) |
		 FIELD_PREP(XSC_EQ_DB_DATA0_ARM, !!arm);

	/* make sure val write to memory done */
	wmb();
	writel(db, xdev->bar + DB_EQ_FUNC_MEM_ADDR);
}

void xsc_update_cmdq_req_pid(struct xsc_core_device *xdev, u32 req_pid)
{
	xsc_write32(xdev->bar, CMDQM_HOST_REQ_PID_MEM_ADDR, req_pid);
}

void xsc_update_cmdq_rsp_cid(struct xsc_core_device *xdev, u32 rsp_cid)
{
	xsc_write32(xdev->bar, CMDQM_HOST_RSP_CID_MEM_ADDR, rsp_cid);
}

u32 xsc_get_cmdq_req_pid(struct xsc_core_device *xdev)
{
	return xsc_read32(xdev->bar, CMDQM_HOST_REQ_PID_MEM_ADDR);
}

u32 xsc_get_cmdq_rsp_pid(struct xsc_core_device *xdev)
{
	return xsc_read32(xdev->bar, CMDQM_HOST_RSP_PID_MEM_ADDR);
}

u32 xsc_get_cmdq_rsp_cid(struct xsc_core_device *xdev)
{
	return xsc_read32(xdev->bar, CMDQM_HOST_RSP_CID_MEM_ADDR);
}

void xsc_set_cmdq_req_buf_addr(struct xsc_core_device *xdev, u32 haddr,
			       u32 laddr)
{
	xsc_write32(xdev->bar, CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR, haddr);
	xsc_write32(xdev->bar, CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR, laddr);
}

void xsc_set_cmdq_rsp_buf_addr(struct xsc_core_device *xdev, u32 haddr,
			       u32 laddr)
{
	xsc_write32(xdev->bar, CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR, haddr);
	xsc_write32(xdev->bar, CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR, laddr);
}

u32 xsc_read_cmdq_err_status(struct xsc_core_device *xdev)
{
	return xsc_read32(xdev->bar, CMDQM_HOST_VF_ERR_STS_MEM_ADDR);
}

void xsc_clear_cmdq_err_status(struct xsc_core_device *xdev, u32 status)
{
	if (status)
		xsc_write32(xdev->bar, CMDQM_HOST_VF_ERR_STS_MEM_ADDR, status);
}
