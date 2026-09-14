// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, MediaTek Inc.
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "mtk_cldma_drv.h"
#include "mtk_dev.h"
#include "mtk_pci.h"
#include "mtk_pci_reg.h"

#define WAIT_QUEUE_STOP		(70)

void mtk_cldma_drv_init(struct cldma_drv_info *drv_info)
{
	struct cldma_hw_regs *hw_regs;
	struct mtk_md_dev *mdev;
	int base;
	u32 val;

	mdev = drv_info->mdev;
	base = drv_info->base_addr;
	hw_regs = drv_info->hw_regs;

	/* set CLDMA to 64 bit mode GPD */
	val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_ul_cfg);
	val = (val & (~(0x7 << 5))) | ((0x4) << 5);
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_ul_cfg, val);

	val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_so_cfg);
	val = (val & (~(0x7 << 10))) | ((0x4) << 10) | (1 << 2);
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_so_cfg, val);

	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_rx_work_to_reg_mask_set, ALLQ);
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_ip_busy_to_pcie_mask_set,
			ALLQ << 16);
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_ip_busy_to_pcie_mask_clr,
			ALLQ << 24);

	/* enable interrupt to PCIe */
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_int_mask, 0);

	/* disable illegal memory check */
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_ul_dummy_0, 1);
	mtk_pci_write32(mdev, base + hw_regs->reg_cldma_so_dummy_0, 1);
}

void mtk_cldma_setup_start_addr(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
				u32 qno, dma_addr_t addr)
{
	struct cldma_hw_regs *hw_regs;
	unsigned int addr_l;
	unsigned int addr_h;
	int base;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX) {
		addr_l = base + hw_regs->reg_cldma_ul_start_addrl_0 + qno * HW_QUEUE_NUM;
		addr_h = base + hw_regs->reg_cldma_ul_start_addrh_0 + qno * HW_QUEUE_NUM;
	} else {
		addr_l = base + hw_regs->reg_cldma_so_start_addrl_0 + qno * HW_QUEUE_NUM;
		addr_h = base + hw_regs->reg_cldma_so_start_addrh_0 + qno * HW_QUEUE_NUM;
	}

	mtk_pci_write32(drv_info->mdev, addr_l, (u32)addr);
	mtk_pci_write32(drv_info->mdev, addr_h, (u32)((u64)addr >> 32));
}

void mtk_cldma_mask_intr(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
			 u32 qno, enum mtk_intr_type type)
{
	struct cldma_hw_regs *hw_regs;
	int base;
	u32 addr;
	u32 val;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_l2timsr0;
	else
		addr = base + hw_regs->reg_cldma_l2rimsr0;

	if (qno == ALLQ)
		val = qno << type;
	else
		val = BIT(qno) << type;

	mtk_pci_write32(drv_info->mdev, addr, val);
}

void mtk_cldma_unmask_intr(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
			   u32 qno, enum mtk_intr_type type)
{
	struct cldma_hw_regs *hw_regs;
	int base;
	u32 addr;
	u32 val;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_l2timcr0;
	else
		addr = base + hw_regs->reg_cldma_l2rimcr0;

	if (qno == ALLQ)
		val = qno << type;
	else
		val = BIT(qno) << type;

	mtk_pci_write32(drv_info->mdev, addr, val);
}

void mtk_cldma_clr_intr_status(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
			       u32 qno, enum mtk_intr_type type)
{
	struct cldma_hw_regs *hw_regs;
	struct mtk_md_dev *mdev;
	int base;
	u32 addr;
	u32 val;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;
	mdev = drv_info->mdev;

	if (type == QUEUE_ERROR) {
		if (dir == DIR_TX) {
			val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l3tisar0);
			mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l3tisar0, val);
			val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l3tisar1);
			mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l3tisar1, val);
			val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l3tisar2);
			mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l3tisar2, val);
		} else {
			val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l3risar0);
			mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l3risar0, val);
			val = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l3risar1);
			mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l3risar1, val);
		}
	}

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_l2tisar0;
	else
		addr = base + hw_regs->reg_cldma_l2risar0;

	if (qno == ALLQ)
		val = qno << type;
	else
		val = BIT(qno) << type;

	mtk_pci_write32(mdev, addr, val);
	val = mtk_pci_read32(mdev, addr);
}

u32 mtk_cldma_check_intr_status(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
				u32 qno, enum mtk_intr_type type)
{
	struct cldma_hw_regs *hw_regs;
	u32 addr, val, sta;
	int base;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_l2tisar0;
	else
		addr = base + hw_regs->reg_cldma_l2risar0;

	val = mtk_pci_read32(drv_info->mdev, addr);
	if (val == LINK_ERROR_VAL)
		sta = val;
	else if (qno == ALLQ)
		sta = (val >> type) & 0xFF;
	else
		sta = (val >> type) & BIT(qno);

	return sta;
}

void mtk_cldma_start_queue(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno)
{
	struct cldma_hw_regs *hw_regs;
	u32 val = BIT(qno);
	int base;
	u32 addr;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_ul_start_cmd;
	else
		addr = base + hw_regs->reg_cldma_so_start_cmd;

	mtk_pci_write32(drv_info->mdev, addr, val);
}

void mtk_cldma_resume_queue(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno)
{
	struct cldma_hw_regs *hw_regs;
	u32 val = BIT(qno);
	int base;
	u32 addr;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_ul_resume_cmd;
	else
		addr = base + hw_regs->reg_cldma_so_resume_cmd;

	mtk_pci_write32(drv_info->mdev, addr, val);
}

u32 mtk_cldma_queue_status(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno)
{
	struct cldma_hw_regs *hw_regs;
	int base;
	u32 addr;
	u32 val;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_ul_status;
	else
		addr = base + hw_regs->reg_cldma_so_status;

	val = mtk_pci_read32(drv_info->mdev, addr);

	if (qno == ALLQ || val == LINK_ERROR_VAL)
		return val;

	return val & BIT(qno);
}

int mtk_cldma_stop_queue(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno)
{
	u32 val = (qno == ALLQ) ? qno : BIT(qno);
	struct cldma_hw_regs *hw_regs;
	unsigned int active;
	int base;
	u32 addr;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;

	if (dir == DIR_TX)
		addr = base + hw_regs->reg_cldma_ul_stop_cmd;
	else
		addr = base + hw_regs->reg_cldma_so_stop_cmd;

	mtk_pci_write32(drv_info->mdev, addr, val);

	if (read_poll_timeout(mtk_cldma_queue_status, active,
			      active == LINK_ERROR_VAL || !active,
			      WAIT_QUEUE_STOP, WAIT_QUEUE_STOP * 10, false,
			      drv_info, dir, qno))
		return -ETIMEDOUT;

	/* An all-ones read means the link is dead, not that the queue
	 * stopped; let the caller tell the two apart.
	 */
	if (active == LINK_ERROR_VAL)
		return -ENODEV;

	return 0;
}

void mtk_cldma_clear_ip_busy(struct cldma_drv_info *drv_info)
{
	mtk_pci_write32(drv_info->mdev, drv_info->base_addr +
			drv_info->hw_regs->reg_cldma_ip_busy, 0x01);
}

void mtk_cldma_get_intr_status(struct cldma_drv_info *drv_info, u32 *tx_sta, u32 *rx_sta)
{
	struct cldma_hw_regs *hw_regs;
	struct mtk_md_dev *mdev;
	u32 tx_mask, rx_mask;
	int base;

	mdev = drv_info->mdev;
	base = drv_info->base_addr;
	hw_regs = drv_info->hw_regs;

	*tx_sta = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l2tisar0);
	tx_mask = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l2timr0);
	*rx_sta = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l2risar0);
	rx_mask = mtk_pci_read32(mdev, base + hw_regs->reg_cldma_l2rimr0);

	*tx_sta = (*tx_sta) & (~tx_mask);
	*rx_sta = (*rx_sta) & (~rx_mask);

	if (*tx_sta) {
		/* TX XFER_DONE and QUEUE_ERROR mask */
		mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l2timsr0, *tx_sta);
		/* TX XFER_DONE clear */
		mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l2tisar0,
				(*tx_sta) & (0xFF << QUEUE_XFER_DONE));
	}

	if (*rx_sta) {
		/* RX XFER_DONE and QUEUE_ERROR mask */
		mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l2rimsr0, *rx_sta);
		/* RX XFER_DONE clear */
		mtk_pci_write32(mdev, base + hw_regs->reg_cldma_l2risar0,
				(*rx_sta) & (0xFF << QUEUE_XFER_DONE));
	}
}

u64 mtk_cldma_get_tx_start_addr(struct cldma_drv_info *drv_info, u32 qno)
{
	struct cldma_hw_regs *hw_regs = drv_info->hw_regs;
	struct mtk_md_dev *mdev = drv_info->mdev;
	int base = drv_info->base_addr;
	u32 addr_h, addr_l;

	addr_l = mtk_pci_read32(mdev,
				base + hw_regs->reg_cldma_ul_start_addrl_0 + qno * HW_QUEUE_NUM);
	addr_h = mtk_pci_read32(mdev,
				base + hw_regs->reg_cldma_ul_start_addrh_0 + qno * HW_QUEUE_NUM);

	return ((u64)addr_h << 32) | addr_l;
}

u64 mtk_cldma_get_rx_curr_addr(struct cldma_drv_info *drv_info, u32 qno)
{
	struct cldma_hw_regs *hw_regs;
	u32 curr_addr_h, curr_addr_l;
	struct mtk_md_dev *mdev;
	u64 curr_addr;
	int base;
	u64 addr;

	hw_regs = drv_info->hw_regs;
	base = drv_info->base_addr;
	mdev = drv_info->mdev;

	addr = base + hw_regs->reg_cldma_so_current_addrh_0 +
	       (u64)qno * HW_QUEUE_NUM;
	curr_addr_h = mtk_pci_read32(mdev, addr);
	addr = base + hw_regs->reg_cldma_so_current_addrl_0 +
	       (u64)qno * HW_QUEUE_NUM;
	curr_addr_l = mtk_pci_read32(mdev, addr);
	curr_addr = ((u64)curr_addr_h << 32) | curr_addr_l;
	if (curr_addr_h == LINK_ERROR_VAL && curr_addr_l == LINK_ERROR_VAL)
		curr_addr = 0;
	return curr_addr;
}
