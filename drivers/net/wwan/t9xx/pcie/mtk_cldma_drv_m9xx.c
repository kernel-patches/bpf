// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, MediaTek Inc.
 */

#include <linux/delay.h>
#include <linux/device.h>
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

#include "mtk_cldma.h"
#include "mtk_cldma_drv.h"
#include "mtk_cldma_drv_m9xx.h"
#include "mtk_dev.h"
#include "mtk_pci.h"
#include "mtk_pci_reg.h"
#include "mtk_trans_ctrl.h"

struct cldma_hw_regs mtk_cldma_regs_m9xx = {
	.cldma0_base_addr = CLDMA0_BASE_ADDR,
	.cldma1_base_addr = CLDMA1_BASE_ADDR,
	.cldma_rx_skb_pool_max_size = CLDMA_RX_SKB_POOL_MAX_SIZE,
	.cldma_rx_skb_reload_threshold = CLDMA_RX_SKB_RELOAD_THRESHOLD,
	.tq_err_int_offset = TQ_ERR_INT_OFFSET,
	.tq_err_int_bitmask = TQ_ERR_INT_BITMASK,
	.tq_active_start_err_int_offset = TQ_ACTIVE_START_ERR_INT_OFFSET,
	.tq_active_start_err_int_bitmask = TQ_ACTIVE_START_ERR_INT_BITMASK,
	.rq_err_int_offset = RQ_ERR_INT_OFFSET,
	.rq_err_int_bitmask = RQ_ERR_INT_BITMASK,
	.rq_active_start_err_int_offset = RQ_ACTIVE_START_ERR_INT_OFFSET,
	.rq_active_start_err_int_bitmask = RQ_ACTIVE_START_ERR_INT_BITMASK,
	.reg_cldma_ul_start_addrl_0 = REG_CLDMA_UL_START_ADDRL_0,
	.reg_cldma_ul_start_addrh_0 = REG_CLDMA_UL_START_ADDRH_0,
	.reg_cldma_ul_current_addrl_0 = REG_CLDMA_UL_CURRENT_ADDRL_0,
	.reg_cldma_ul_current_addrh_0 = REG_CLDMA_UL_CURRENT_ADDRH_0,
	.reg_cldma_ul_status = REG_CLDMA_UL_STATUS,
	.reg_cldma_ul_start_cmd = REG_CLDMA_UL_START_CMD,
	.reg_cldma_ul_resume_cmd = REG_CLDMA_UL_RESUME_CMD,
	.reg_cldma_ul_stop_cmd = REG_CLDMA_UL_STOP_CMD,
	.reg_cldma_ul_error = REG_CLDMA_UL_ERROR,
	.reg_cldma_ul_cfg = REG_CLDMA_UL_CFG,
	.reg_cldma_ul_dummy_0 = REG_CLDMA_UL_DUMMY_0,
	.reg_cldma_so_error = REG_CLDMA_SO_ERROR,
	.reg_cldma_so_start_cmd = REG_CLDMA_SO_START_CMD,
	.reg_cldma_so_resume_cmd = REG_CLDMA_SO_RESUME_CMD,
	.reg_cldma_so_stop_cmd = REG_CLDMA_SO_STOP_CMD,
	.reg_cldma_so_dummy_0 = REG_CLDMA_SO_DUMMY_0,
	.reg_cldma_so_cfg = REG_CLDMA_SO_CFG,
	.reg_cldma_so_start_addrl_0 = REG_CLDMA_SO_START_ADDRL_0,
	.reg_cldma_so_start_addrh_0 = REG_CLDMA_SO_START_ADDRH_0,
	.reg_cldma_so_current_addrl_0 = REG_CLDMA_SO_CUR_ADDRL_0,
	.reg_cldma_so_current_addrh_0 = REG_CLDMA_SO_CUR_ADDRH_0,
	.reg_cldma_so_status = REG_CLDMA_SO_STATUS,
	.reg_cldma_debug_id_en = REG_CLDMA_DEBUG_ID_EN,
	.reg_cldma_so_last_update_addrl_0 = REG_CLDMA_SO_LAST_UPDATE_ADDRL_0,
	.reg_cldma_so_last_update_addrh_0 = REG_CLDMA_SO_LAST_UPDATE_ADDRH_0,
	.reg_cldma_l2tisar0 = REG_CLDMA_L2TISAR0,
	.reg_cldma_l2tisar1 = REG_CLDMA_L2TISAR1,
	.reg_cldma_l2timr0 = REG_CLDMA_L2TIMR0,
	.reg_cldma_l2timr1 = REG_CLDMA_L2TIMR1,
	.reg_cldma_l2timcr0 = REG_CLDMA_L2TIMCR0,
	.reg_cldma_l2timcr1 = REG_CLDMA_L2TIMCR1,
	.reg_cldma_l2timsr0 = REG_CLDMA_L2TIMSR0,
	.reg_cldma_l2timsr1 = REG_CLDMA_L2TIMSR1,
	.reg_cldma_l3tisar0 = REG_CLDMA_L3TISAR0,
	.reg_cldma_l3tisar1 = REG_CLDMA_L3TISAR1,
	.reg_cldma_l3tisar2 = REG_CLDMA_L3TISAR2,
	.reg_cldma_l2risar0 = REG_CLDMA_L2RISAR0,
	.reg_cldma_l2risar1 = REG_CLDMA_L2RISAR1,
	.reg_cldma_l2rimr0 = REG_CLDMA_L2RIMR0,
	.reg_cldma_l2rimr1 = REG_CLDMA_L2RIMR1,
	.reg_cldma_l2rimcr0 = REG_CLDMA_L2RIMCR0,
	.reg_cldma_l2rimcr1 = REG_CLDMA_L2RIMCR1,
	.reg_cldma_l2rimsr0 = REG_CLDMA_L2RIMSR0,
	.reg_cldma_l2rimsr1 = REG_CLDMA_L2RIMSR1,
	.reg_cldma_l3risar0 = REG_CLDMA_L3RISAR0,
	.reg_cldma_l3risar1 = REG_CLDMA_L3RISAR1,
	.reg_cldma_ip_busy = REG_CLDMA_IP_BUSY,
	.reg_cldma_int_mask = REG_CLDMA_INT_EAP_USIP_MASK,
	.reg_cldma_ip_busy_to_pcie_mask = REG_CLDMA_IP_BUSY_TO_PCIE_MASK,
	.reg_cldma_ip_busy_to_pcie_mask_set = REG_CLDMA_IP_BUSY_TO_PCIE_MASK_SET,
	.reg_cldma_ip_busy_to_pcie_mask_clr = REG_CLDMA_IP_BUSY_TO_PCIE_MASK_CLR,
	.reg_cldma_ip_busy_to_ap_mask = REG_CLDMA_IP_BUSY_TO_AP_MASK,
	.reg_cldma_ip_busy_to_ap_mask_set = REG_CLDMA_IP_BUSY_TO_AP_MASK_SET,
	.reg_cldma_ip_busy_to_ap_mask_clr = REG_CLDMA_IP_BUSY_TO_AP_MASK_CLR,
	.reg_cldma_ip_busy_to_md_mask_set = REG_CLDMA_IP_BUSY_TO_MD_MASK_SET,
	.reg_cldma_rx_work_to_reg_mask_set = REG_CLDMA_RX_WORK_TO_REG_MASK_SET,
	.reg_infra_rst0_set = REG_INFRA_RST0_SET,
	.reg_infra_rst0_clr = REG_INFRA_RST0_CLR,
};

static void mtk_cldma_drv_init_m9xx(struct cldma_drv_info *drv_info)
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

static void mtk_cldma_drv_reset_m9xx(struct cldma_drv_info *drv_info)
{
	struct cldma_hw_regs *hw_regs;
	struct mtk_md_dev *mdev;
	u32 val;

	mdev = drv_info->mdev;
	hw_regs = drv_info->hw_regs;

	val = mtk_pci_read32(mdev, REG_DEV_INFRA_BASE + hw_regs->reg_infra_rst0_set);

	val |= 1 << (REG_CLDMA0_RST_SET_BIT + drv_info->hw_id);
	mtk_pci_write32(mdev, REG_DEV_INFRA_BASE + hw_regs->reg_infra_rst0_set, val);
	udelay(1);
	val = mtk_pci_read32(mdev, REG_DEV_INFRA_BASE + hw_regs->reg_infra_rst0_clr);
	val |= 1 << (REG_CLDMA0_RST_CLR_BIT + drv_info->hw_id);
	mtk_pci_write32(mdev, REG_DEV_INFRA_BASE + hw_regs->reg_infra_rst0_clr, val);
}

struct cldma_drv_ops cldma_drv_ops_m9xx = {
	.cldma_drv_init = mtk_cldma_drv_init_m9xx,
	.cldma_drv_reset = mtk_cldma_drv_reset_m9xx,
	.cldma_setup_start_addr = mtk_cldma_setup_start_addr,
	.cldma_mask_intr = mtk_cldma_mask_intr,
	.cldma_unmask_intr = mtk_cldma_unmask_intr,
	.cldma_clr_intr_status = mtk_cldma_clr_intr_status,
	.cldma_check_intr_status = mtk_cldma_check_intr_status,
	.cldma_start_queue = mtk_cldma_start_queue,
	.cldma_resume_queue = mtk_cldma_resume_queue,
	.cldma_queue_status = mtk_cldma_queue_status,
	.cldma_stop_queue = mtk_cldma_stop_queue,
	.cldma_clear_ip_busy = mtk_cldma_clear_ip_busy,
	.cldma_get_intr_status = mtk_cldma_get_intr_status,
	.cldma_get_tx_start_addr = mtk_cldma_get_tx_start_addr,
	.cldma_get_rx_curr_addr = mtk_cldma_get_rx_curr_addr,
};
