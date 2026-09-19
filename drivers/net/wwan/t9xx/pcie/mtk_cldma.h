/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_CLDMA_H__
#define __MTK_CLDMA_H__

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "mtk_ctrl_plane.h"
#include "mtk_trans_ctrl.h"

struct mtk_fsm_param;

#define TXQ(N)					(N)
#define RXQ(N)					(N)

#define CLDMA_GPD_FLAG_HWO			BIT(0)
#define CLDMA_GPD_FLAG_BDP			BIT(1)
#define CLDMA_GPD_FLAG_BPS			BIT(2)
#define CLDMA_GPD_FLAG_IOC			BIT(7)
#define CLDMA_BD_FLAG_EOL			BIT(0)

union gpd {
	struct {
		u8 gpd_flags;
		u8 non_used1;
		__le16 data_allow_len;
		__le32 next_gpd_ptr_h;
		__le32 next_gpd_ptr_l;
		__le32 data_buff_ptr_h;
		__le32 data_buff_ptr_l;
		__le16 data_recv_len;
		u8 non_used2;
		u8 debug_id;
	} rx_gpd;

	struct {
		u8 gpd_flags;
		u8 non_used1;
		u8 non_used2;
		u8 debug_id;
		__le32 next_gpd_ptr_h;
		__le32 next_gpd_ptr_l;
		__le32 data_buff_ptr_h;
		__le32 data_buff_ptr_l;
		__le16 data_buff_len;
		__le16 non_used3;
	} tx_gpd;
} __packed;

union bd {
	struct {
		u8 bd_flags;
		u8 non_used1;
		__le16 data_allow_len;
		__le32 next_bd_ptr_h;
		__le32 next_bd_ptr_l;
		__le32 data_buff_ptr_h;
		__le32 data_buff_ptr_l;
		__le16 data_recv_len;
		__le16 non_used2;
	} rx_bd;

	struct {
		u8 bd_flags;
		u8 non_used1;
		__le16 non_used2;
		__le32 next_bd_ptr_h;
		__le32 next_bd_ptr_l;
		__le32 data_buff_ptr_h;
		__le32 data_buff_ptr_l;
		__le16 data_buffer_len;
		u8 extension_len;
		u8 non_used3;
	} tx_bd;
} __packed;

struct bd_dsc {
	union bd *bd;
	struct sk_buff *skb;
	dma_addr_t bd_dma_addr;
	dma_addr_t data_dma_addr;
	size_t data_len;
};

struct rx_req {
	union gpd *gpd;
	u32 mtu;
	struct sk_buff *skb;
	size_t data_len;
	dma_addr_t gpd_dma_addr;
	dma_addr_t data_dma_addr;
	u32 frag_size;
	struct bd_dsc *bd_dsc_pool;
};

struct rxq {
	struct cldma_drv_info *drv_info;
	u32 rxqno;
	struct queue_info *que;
	struct work_struct rx_done_work;
	struct rx_req *req_pool;
	u32 nr_gpds;
	u32 free_idx;
	unsigned short rx_done_cnt;
	void *arg;
	int (*rx_done)(struct sk_buff *skb, void *priv, bool force_recv);
	u32 nr_bds;
	atomic_t need_exit;
	/* set when the queue must be programmed and started again after an IP
	 * reset; consumed by mtk_cldma_rx_done_work(), the owner of free_idx
	 */
	atomic_t need_restart;
};

struct tx_req {
	union gpd *gpd;
	u32 mtu;
	size_t data_len;
	dma_addr_t data_dma_addr;
	dma_addr_t gpd_dma_addr;
	struct sk_buff *skb;
	int (*trb_complete)(struct sk_buff *skb);
	u32 frag_size;
	struct bd_dsc *bd_dsc_pool;
};

struct txq {
	struct cldma_drv_info *drv_info;
	u32 txqno;
	struct queue_info *que;
	struct work_struct tx_done_work;
	struct tx_req *req_pool;
	u32 nr_gpds;
	atomic_t req_budget;
	/* ring_lock: serializes the producer (TRB service thread) against the
	 * consumer (tx_done_work) over req_budget, wr_idx, free_idx and the
	 * tx_req/GPD slots they index.
	 */
	spinlock_t ring_lock;
	u32 wr_idx;
	u32 free_idx;
	bool tx_started;
	bool is_stopping;
	unsigned short tx_done_cnt;
	u32 nr_bds;
};

struct cldma_dev {
	struct cldma_drv_info *cldma_drv_info[NR_CLDMA];
	struct mtk_ctrl_trans *trans;
};

struct cldma_drv_info_desc {
	u32 hw_ver;
	struct cldma_drv_ops *drv_ops;
	struct cldma_hw_regs *hw_regs;
};

int mtk_cldma_init(struct mtk_ctrl_trans *trans);
void mtk_cldma_exit(struct mtk_ctrl_trans *trans);
int mtk_cldma_submit_tx(void *dev, struct sk_buff *skb);
int mtk_cldma_get_tx_budget(void *dev, enum mtk_hif_id hif_id, u32 qno);
int mtk_cldma_trb_process(void *dev, struct sk_buff *skb);
void mtk_cldma_fsm_state_listener(struct mtk_fsm_param *param, struct mtk_ctrl_trans *trans);
int mtk_cldma_check_ch_cfg(void *dev, struct queue_info *que);

#define drv_ops_name(NAME) cldma_drv_ops_##NAME
#define cldma_regs_name(NAME) mtk_cldma_regs_##NAME

extern struct cldma_drv_ops cldma_drv_ops_m9xx;
extern struct cldma_hw_regs mtk_cldma_regs_m9xx;

#endif
