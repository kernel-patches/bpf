/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2023, MediaTek Inc.
 */

#ifndef __MTK_CLDMA_DRV_H__
#define __MTK_CLDMA_DRV_H__

#include "mtk_trans_ctrl.h"

#define ALLQ			(0xFF)
#define LINK_ERROR_VAL		(0xFFFFFFFF)
#define CLDMA0_HW_ID		(0)
#define CLDMA1_HW_ID		(1)

struct cldma_hw_regs {
	u16 reg_cldma_so_cfg;
	u16 reg_cldma_so_start_addrl_0;
	u16 reg_cldma_so_start_addrh_0;
	u16 reg_cldma_so_current_addrl_0;
	u16 reg_cldma_so_current_addrh_0;
	u16 reg_cldma_so_status;
	u16 reg_cldma_l2rimr0;
	u16 reg_cldma_l2rimcr0;
	u16 reg_cldma_l2rimsr0;
	u16 reg_cldma_int_mask;
	u16 reg_cldma_ip_busy_to_pcie_mask_set;
	u16 reg_cldma_ip_busy_to_pcie_mask_clr;
	u16 reg_cldma_rx_work_to_reg_mask_set;
	u16 reg_infra_rst0_set;
	u16 reg_infra_rst0_clr;
	u32 cldma0_base_addr;
	u32 cldma1_base_addr;
	u32 reg_cldma_ul_start_addrl_0;
	u32 reg_cldma_ul_start_addrh_0;
	u32 reg_cldma_ul_status;
	u32 reg_cldma_ul_start_cmd;
	u32 reg_cldma_ul_resume_cmd;
	u32 reg_cldma_ul_stop_cmd;
	u32 reg_cldma_ul_cfg;
	u32 reg_cldma_ul_dummy_0;
	u32 reg_cldma_so_start_cmd;
	u32 reg_cldma_so_resume_cmd;
	u32 reg_cldma_so_stop_cmd;
	u32 reg_cldma_so_dummy_0;
	u32 reg_cldma_l2tisar0;
	u32 reg_cldma_l2timr0;
	u32 reg_cldma_l2timcr0;
	u32 reg_cldma_l2timsr0;
	u32 reg_cldma_l2risar0;
	u32 reg_cldma_l3tisar0;
	u32 reg_cldma_l3tisar1;
	u32 reg_cldma_l3tisar2;
	u32 reg_cldma_l3risar0;
	u32 reg_cldma_l3risar1;
	u32 reg_cldma_ip_busy;
};

enum mtk_intr_type {
	QUEUE_XFER_DONE = 0,
	QUEUE_ERROR = 16,
};

enum mtk_tx_rx {
	DIR_TX,
	DIR_RX,
};

struct cldma_drv_info {
	int hif_id;
	int hw_id;
	int base_addr;
	int pci_ext_irq_id;
	struct mtk_md_dev *mdev;
	struct cldma_dev *cd;
	struct txq *txq[HW_QUE_NUM];
	struct rxq *rxq[HW_QUE_NUM];
	struct dma_pool *gpd_dma_pool;
	struct workqueue_struct *wq;
	const struct cldma_hw_regs *hw_regs;
	struct work_struct err_work;
	atomic_t tx_err_qs;
	atomic_t rx_err_qs;
	/* a ring could not be stopped and was leaked on free */
	bool ring_leaked;
	/* this instance's interrupt and workers have already been retired;
	 * makes the quiesce safe to repeat on the teardown path
	 */
	bool quiesced;
	/* serialises the instance reset and re-arm against queue kicks and
	 * RX resume/restart, and re-arming against setting quiesced
	 */
	struct mutex rearm_lock;
};

extern const struct cldma_hw_regs mtk_cldma_regs_m9xx;

void mtk_cldma_drv_init(struct cldma_drv_info *drv_info);
void mtk_cldma_drv_reset(struct cldma_drv_info *drv_info);
void mtk_cldma_setup_start_addr(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
				u32 qno, dma_addr_t addr);
void mtk_cldma_mask_intr(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
			 u32 qno, enum mtk_intr_type type);
void mtk_cldma_unmask_intr(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
			   u32 qno, enum mtk_intr_type type);
void mtk_cldma_clr_intr_status(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
			       u32 qno, enum mtk_intr_type type);
u32 mtk_cldma_check_intr_status(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir,
				u32 qno, enum mtk_intr_type type);
void mtk_cldma_start_queue(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno);
void mtk_cldma_resume_queue(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno);
int mtk_cldma_stop_queue(struct cldma_drv_info *drv_info, enum mtk_tx_rx dir, u32 qno);
void mtk_cldma_clear_ip_busy(struct cldma_drv_info *drv_info);
void mtk_cldma_get_intr_status(struct cldma_drv_info *drv_info, u32 *tx_sta, u32 *rx_sta);
u64 mtk_cldma_get_tx_start_addr(struct cldma_drv_info *drv_info, u32 qno);
u64 mtk_cldma_get_rx_curr_addr(struct cldma_drv_info *drv_info, u32 qno);

#endif
