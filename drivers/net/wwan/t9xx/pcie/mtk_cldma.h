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
#define CLDMA_GPD_FLAG_IOC			BIT(7)

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

struct rx_req {
	union gpd *gpd;
	u32 mtu;
	struct sk_buff *skb;
	dma_addr_t gpd_dma_addr;
	dma_addr_t data_dma_addr;
};

struct rxq {
	struct cldma_drv_info *drv_info;
	u32 rxqno;
	struct queue_info *que;
	struct work_struct rx_done_work;
	struct rx_req *req_pool;
	u32 nr_gpds;
	u32 free_idx;
	void *arg;
	/* consumes the skb; the return value is informational */
	int (*rx_done)(struct sk_buff *skb, void *priv);
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
};

struct cldma_dev {
	struct cldma_drv_info *cldma_drv_info[NR_CLDMA];
	struct mtk_ctrl_trans *trans;
};

int mtk_cldma_init(struct mtk_ctrl_trans *trans);
void mtk_cldma_exit(struct mtk_ctrl_trans *trans);
int mtk_cldma_submit_tx(void *dev, struct sk_buff *skb);
int mtk_cldma_get_tx_budget(void *dev, enum mtk_hif_id hif_id, u32 qno);
int mtk_cldma_trb_process(void *dev, struct sk_buff *skb);
void mtk_cldma_fsm_state_listener(struct mtk_fsm_param *param, struct mtk_ctrl_trans *trans);
int mtk_cldma_check_ch_cfg(void *dev, struct queue_info *que);

#endif
