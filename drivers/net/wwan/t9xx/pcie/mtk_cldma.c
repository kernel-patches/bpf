// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
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
#include "mtk_pci.h"
#include "mtk_cldma.h"
#include "mtk_cldma_drv.h"
#include "mtk_dev.h"

#define DMA_POOL_NAME_LEN	(64)
#define WAIT_HWO_ROUND		(10)
#define WAIT_HWO_TIME		(5)
#define NO_BUDGET		(0)

static struct cldma_drv_info_desc cldma_drv_info_tbl[] = {
	{0x0900, &drv_ops_name(m9xx), &cldma_regs_name(m9xx)},
	{0x01CA, &drv_ops_name(m9xx), &cldma_regs_name(m9xx)},
	{0, NULL},
};

static void mtk_cldma_err_work(struct work_struct *work);

static void mtk_cldma_get_drv_info(struct cldma_drv_info *drv_info, u32 hw_ver)
{
	struct cldma_drv_info_desc *p_drv_info;
	u8 i;

	for (i = 0; (p_drv_info = &cldma_drv_info_tbl[i]) && p_drv_info &&
	     p_drv_info->drv_ops && p_drv_info->hw_regs; i++)
		if (p_drv_info->hw_ver == hw_ver) {
			drv_info->drv_ops = p_drv_info->drv_ops;
			drv_info->hw_regs = p_drv_info->hw_regs;
		}
}

static int mtk_cldma_isr(int irq_id, void *param)
{
	struct cldma_drv_info *drv_info = param;
	u32 tx_err, rx_err;
	struct mtk_md_dev *mdev;
	u32 tx_done, rx_done;
	u32 tx_sta, rx_sta;
	struct txq *txq;
	struct rxq *rxq;
	int i;

	mdev = drv_info->mdev;
	drv_info->drv_ops->cldma_get_intr_status(drv_info, &tx_sta, &rx_sta);
	tx_done = (tx_sta >> QUEUE_XFER_DONE) & 0xFF;
	rx_done = (rx_sta >> QUEUE_XFER_DONE) & 0xFF;
	tx_err = (tx_sta >> QUEUE_ERROR) & 0xFF;
	rx_err = (rx_sta >> QUEUE_ERROR) & 0xFF;

	if (tx_err || rx_err) {
		dev_err_ratelimited(mdev->dev, "CLDMA%d queue error: TX 0x%x RX 0x%x\n",
				    drv_info->hif_id, tx_err, rx_err);
		for (i = 0; i < HW_QUEUE_NUM; i++) {
			if (tx_err & BIT(i)) {
				drv_info->drv_ops->cldma_clr_intr_status(drv_info, DIR_TX,
									 i, QUEUE_ERROR);
				drv_info->drv_ops->cldma_unmask_intr(drv_info, DIR_TX,
								     i, QUEUE_ERROR);
			}
			if (rx_err & BIT(i)) {
				drv_info->drv_ops->cldma_clr_intr_status(drv_info, DIR_RX,
									 i, QUEUE_ERROR);
				drv_info->drv_ops->cldma_unmask_intr(drv_info, DIR_RX,
								     i, QUEUE_ERROR);
			}
		}
		atomic_or(tx_err, &drv_info->tx_err_qs);
		atomic_or(rx_err, &drv_info->rx_err_qs);
		queue_work(drv_info->wq, &drv_info->err_work);
	}

	if (tx_done) {
		for (i = 0; i < HW_QUEUE_NUM; i++) {
			/* pairs with smp_store_release() in txq_alloc */
			txq = smp_load_acquire(&drv_info->txq[i]);
			if (!(tx_done & BIT(i)) || !txq)
				continue;
			queue_work(drv_info->wq, &txq->tx_done_work);
		}
	}
	if (rx_done) {
		for (i = 0; i < HW_QUEUE_NUM; i++) {
			/* pairs with smp_store_release() in rxq_alloc */
			rxq = smp_load_acquire(&drv_info->rxq[i]);
			if (!(rx_done & BIT(i)) || !rxq)
				continue;
			queue_work(drv_info->wq, &rxq->rx_done_work);
		}
	}

	mtk_pci_clear_irq(mdev, drv_info->pci_ext_irq_id);
	mtk_pci_unmask_irq(mdev, drv_info->pci_ext_irq_id);

	return IRQ_HANDLED;
}

static const int mtk_cldma_hw_id_tbl[NR_CLDMA] = {
	[CLDMA0] = CLDMA0_HW_ID,
	[CLDMA1] = CLDMA1_HW_ID,
};

static int mtk_cldma_dev_init(struct cldma_dev *cd, int hif_id)
{
	char gpd_pool_name[DMA_POOL_NAME_LEN];
	char bd_pool_name[DMA_POOL_NAME_LEN];
	struct cldma_drv_info *drv_info;
	struct cldma_hw_regs *hw_regs;
	struct mtk_md_dev *mdev;
	unsigned int flag;
	int hw_id, ret;

	if (!cd || hif_id >= NR_CLDMA)
		return -EINVAL;

	if (cd->cldma_drv_info[hif_id])
		return 0;

	hw_id = mtk_cldma_hw_id_tbl[hif_id];
	mdev = cd->trans->mdev;
	drv_info = kzalloc_obj(*drv_info);
	if (!drv_info)
		return -ENOMEM;

	drv_info->cd = cd;
	drv_info->mdev = mdev;
	drv_info->hif_id = hif_id;
	drv_info->hw_id = hw_id;
	mtk_cldma_get_drv_info(drv_info, mdev->hw_ver);

	if (!drv_info->drv_ops || !drv_info->hw_regs) {
		dev_err(mdev->dev, "Failed to find CLDMA Driver for PCI %x\n", mdev->hw_ver);
		ret = -EIO;
		goto err_free_drv_info;
	}

	hw_regs = drv_info->hw_regs;
	snprintf(gpd_pool_name, DMA_POOL_NAME_LEN, "cldma%d_gpd_pool_%s",
		 hw_id, mdev->dev_str);
	snprintf(bd_pool_name, DMA_POOL_NAME_LEN, "cldma%d_bd_pool_%s",
		 hw_id, mdev->dev_str);
	drv_info->gpd_dma_pool = dma_pool_create(gpd_pool_name, mdev->dev,
						 sizeof(union gpd), 4, 0);
	if (!drv_info->gpd_dma_pool) {
		dev_err(mdev->dev, "Failed to alloc gpd dma pool for cldma%d\n", hw_id);
		ret = -ENOMEM;
		goto err_free_drv_info;
	}
	drv_info->bd_dma_pool = dma_pool_create(bd_pool_name, mdev->dev,
						sizeof(union bd), 4, 0);
	if (!drv_info->bd_dma_pool) {
		dev_err(mdev->dev, "Failed to alloc bd dma pool for cldma%d\n", hw_id);
		ret = -ENOMEM;
		goto err_destroy_gpd_pool;
	}

	switch (hif_id) {
	case CLDMA0:
		drv_info->pci_ext_irq_id = mtk_pci_get_irq_id(mdev, MTK_IRQ_SRC_CLDMA0);
		drv_info->base_addr = hw_regs->cldma0_base_addr;
		break;
	case CLDMA1:
		drv_info->pci_ext_irq_id = mtk_pci_get_irq_id(mdev, MTK_IRQ_SRC_CLDMA1);
		drv_info->base_addr = hw_regs->cldma1_base_addr;
		break;
	default:
		ret = -EINVAL;
		goto err_destroy_dma_pool;
	}

	flag = WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_HIGHPRI;
	drv_info->wq = alloc_workqueue("cldma%d_workq_%s", flag, 0, hw_id, mdev->dev_str);
	if (!drv_info->wq) {
		dev_err(mdev->dev, "Failed to alloc work queue for cldma%d\n", hw_id);
		ret = -ENOMEM;
		goto err_destroy_dma_pool;
	}

	INIT_WORK(&drv_info->err_work, mtk_cldma_err_work);
	atomic_set(&drv_info->tx_err_qs, 0);
	atomic_set(&drv_info->rx_err_qs, 0);

	drv_info->drv_ops->cldma_drv_init(drv_info);

	/* mask/clear PCI CLDMA L1 interrupt */
	mtk_pci_mask_irq(mdev, drv_info->pci_ext_irq_id);
	mtk_pci_clear_irq(mdev, drv_info->pci_ext_irq_id);

	/* register CLDMA interrupt handler */
	ret = mtk_pci_register_irq(mdev, drv_info->pci_ext_irq_id, mtk_cldma_isr, drv_info);
	if (ret)
		goto err_destroy_wq;

	/* unmask PCI CLDMA L1 interrupt */
	mtk_pci_unmask_irq(mdev, drv_info->pci_ext_irq_id);

	cd->cldma_drv_info[hif_id] = drv_info;
	return 0;

err_destroy_wq:
	destroy_workqueue(drv_info->wq);
err_destroy_dma_pool:
	dma_pool_destroy(drv_info->bd_dma_pool);
err_destroy_gpd_pool:
	dma_pool_destroy(drv_info->gpd_dma_pool);
err_free_drv_info:
	kfree(drv_info);

	return ret;
}

static void mtk_cldma_clr_bd_dsc(struct cldma_drv_info *drv_info,
				 struct bd_dsc *bd_dsc_pool, int nr_bds)
{
	struct bd_dsc *bd_dsc;
	int i;

	for (i = 0; i < nr_bds; i++) {
		bd_dsc = bd_dsc_pool + i;
		dma_unmap_single(drv_info->mdev->dev, bd_dsc->data_dma_addr,
				 bd_dsc->data_len, DMA_TO_DEVICE);
		bd_dsc->data_dma_addr = 0;
		bd_dsc->data_len = 0;
		if (bd_dsc->bd->tx_bd.bd_flags & CLDMA_BD_FLAG_EOL) {
			bd_dsc->bd->tx_bd.bd_flags &= ~CLDMA_BD_FLAG_EOL;
			break;
		}
	}
}

static void mtk_cldma_tx_done_work(struct work_struct *work)
{
	struct txq *txq = container_of(work, struct txq, tx_done_work);
	struct cldma_drv_info *drv_info;
	struct cldma_drv_ops *drv_ops;
	struct mtk_ctrl_trans *trans;
	struct mtk_md_dev *mdev;
	struct sk_buff *skb;
	struct tx_req *req;
	unsigned int state;
	bool was_starved;
	struct trb *trb;
	int i, hif_id;
	u32 txqno;

	drv_info = txq->drv_info;
	hif_id = drv_info->hif_id;
	txqno = txq->txqno;
	mdev = drv_info->mdev;
	drv_ops = drv_info->drv_ops;
	trans = drv_info->cd->trans;

again:
	for (i = 0; i < txq->nr_gpds; i++) {
		spin_lock(&txq->ring_lock);

		req = txq->req_pool + txq->free_idx;

		/* Ownership is decided by the slot alone: an empty slot has no
		 * skb, and one the hardware still owns has HWO set. The
		 * producer publishes both under ring_lock, so a slot can never
		 * be observed half-filled and there is no need to bound the
		 * walk by wr_idx.
		 */
		if (!req->skb || (req->gpd->tx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO)) {
			spin_unlock(&txq->ring_lock);
			break;
		}

		dma_rmb(); /* read descriptor fields after HWO check */

		if (txq->nr_bds)
			mtk_cldma_clr_bd_dsc(drv_info, req->bd_dsc_pool, txq->nr_bds);
		else
			dma_unmap_single(mdev->dev, req->data_dma_addr,
					 req->data_len, DMA_TO_DEVICE);

		skb = req->skb;
		req->data_dma_addr = 0;
		req->data_len = 0;
		req->skb = NULL;

		txq->free_idx = (txq->free_idx + 1) % txq->nr_gpds;
		was_starved = atomic_fetch_inc(&txq->req_budget) == NO_BUDGET;

		spin_unlock(&txq->ring_lock);

		trb = (struct trb *)skb->cb;
		trb->status = 0;
		trb->trb_complete(skb);

		if (was_starved)
			wake_up(&trans->trb_srv[trans->srv_cfg[hif_id][txqno]]->trb_waitq);
	}

	state = drv_ops->cldma_check_intr_status(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);
	if (state) {
		if (unlikely(state == LINK_ERROR_VAL))
			goto out;

		drv_ops->cldma_clr_intr_status(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);

		cond_resched();

		goto again;
	}

out:
	drv_ops->cldma_unmask_intr(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);
}

/* Clamp every length the device reports against the length the driver
 * advertised in the matching descriptor (data_allow_len), never against
 * frag_size or mtu: on the last BD of a packet data_allow_len is smaller
 * than frag_size.  Returns -EPROTO when the device over-reports so the
 * caller drops the packet instead of delivering a malformed skb.
 */
static int mtk_cldma_rx_skb_adjust(struct mtk_md_dev *mdev, struct rxq *rxq,
				   struct rx_req *req)
{
	u32 recv_len, allow_len, total_len = 0;
	struct bd_dsc *bd_dsc;
	int ret = 0;
	int i;

	for (i = 0; i < rxq->nr_bds; i++) {
		bd_dsc = req->bd_dsc_pool + i;
		if (bd_dsc->data_dma_addr) {
			dma_unmap_single(mdev->dev, bd_dsc->data_dma_addr,
					 req->frag_size, DMA_FROM_DEVICE);
			bd_dsc->data_dma_addr = 0;
		}
		recv_len = le16_to_cpu(bd_dsc->bd->rx_bd.data_recv_len);
		allow_len = le16_to_cpu(bd_dsc->bd->rx_bd.data_allow_len);
		if (recv_len > allow_len) {
			ret = -EPROTO;
			recv_len = allow_len;
		}
		total_len += recv_len;
		if (total_len > req->mtu) {
			ret = -EPROTO;
			recv_len -= min(total_len - req->mtu, recv_len);
			total_len = req->mtu;
		}
		bd_dsc->skb->len = 0;
		skb_reset_tail_pointer(bd_dsc->skb);
		skb_put(bd_dsc->skb, recv_len);
		if (req->skb != bd_dsc->skb) {
			req->skb->len += bd_dsc->skb->len;
			req->skb->data_len += bd_dsc->skb->len;
		}
		bd_dsc->bd->rx_bd.data_recv_len = 0;
		bd_dsc->skb = NULL;
	}
	if (!rxq->nr_bds) {
		if (req->data_dma_addr) {
			dma_unmap_single(mdev->dev, req->data_dma_addr,
					 req->mtu, DMA_FROM_DEVICE);
			req->data_dma_addr = 0;
		}
		recv_len = le16_to_cpu(req->gpd->rx_gpd.data_recv_len);
		allow_len = le16_to_cpu(req->gpd->rx_gpd.data_allow_len);
		if (recv_len > allow_len) {
			ret = -EPROTO;
			recv_len = allow_len;
		}
		req->skb->len = 0;
		skb_reset_tail_pointer(req->skb);
		skb_put(req->skb, recv_len);
	}

	req->gpd->rx_gpd.data_recv_len = 0;

	return ret;
}

static int mtk_cldma_reload_rx_skb(struct mtk_md_dev *mdev, struct rxq *rxq,
				   struct rx_req *req)
{
	struct sk_buff *tail = NULL;
	struct bd_dsc *bd_dsc;
	int nr_bds;
	int i, ret;

	nr_bds = rxq->nr_bds;

	for (i = 0; i < nr_bds; i++) {
		bd_dsc = req->bd_dsc_pool + i;
		bd_dsc->skb = __dev_alloc_skb(req->frag_size, GFP_KERNEL);
		if (!bd_dsc->skb) {
			dev_warn_ratelimited(mdev->dev, "Failed to alloc SKB\n");
			ret = -ENOMEM;
			goto err_free_skb;
		}
		bd_dsc->skb->next = NULL;
		bd_dsc->data_dma_addr = dma_map_single(mdev->dev, bd_dsc->skb->data,
						       req->frag_size, DMA_FROM_DEVICE);
		ret = dma_mapping_error(mdev->dev, bd_dsc->data_dma_addr);
		if (unlikely(ret)) {
			dev_warn_ratelimited(mdev->dev, "Failed to map SKB data\n");
			ret = -EFAULT;
			goto err_free_skb;
		}
		bd_dsc->bd->rx_bd.data_buff_ptr_h =
			cpu_to_le32((u64)(bd_dsc->data_dma_addr) >> 32);
		bd_dsc->bd->rx_bd.data_buff_ptr_l =
			cpu_to_le32(bd_dsc->data_dma_addr);
		if (tail) {
			tail->next = bd_dsc->skb;
			tail = bd_dsc->skb;
			continue;
		}
		if (!req->skb) {
			req->skb = bd_dsc->skb;
		} else {
			skb_shinfo(req->skb)->frag_list = bd_dsc->skb;
			tail = bd_dsc->skb;
		}
	}
	if (!nr_bds) {
		req->skb = __dev_alloc_skb(req->mtu, GFP_KERNEL);
		if (!req->skb) {
			ret = -ENOMEM;
			goto err_free_skb;
		}

		req->data_dma_addr = dma_map_single(mdev->dev, req->skb->data,
						    req->mtu, DMA_FROM_DEVICE);
		ret = dma_mapping_error(mdev->dev, req->data_dma_addr);
		if (unlikely(ret)) {
			dev_warn_ratelimited(mdev->dev, "Failed to map SKB data\n");
			ret = -EFAULT;
			goto err_free_skb;
		}
		req->gpd->rx_gpd.data_buff_ptr_h = cpu_to_le32((u64)req->data_dma_addr >> 32);
		req->gpd->rx_gpd.data_buff_ptr_l = cpu_to_le32(req->data_dma_addr);
	}
	return 0;

err_free_skb:
	if (nr_bds) {
		if (req->skb)
			skb_shinfo(req->skb)->frag_list = NULL;
		for (i = 0; i < nr_bds; i++) {
			bd_dsc = req->bd_dsc_pool + i;
			if (!bd_dsc->skb)
				break;
			if (!dma_mapping_error(mdev->dev, bd_dsc->data_dma_addr))
				dma_unmap_single(mdev->dev, bd_dsc->data_dma_addr,
						 req->frag_size, DMA_FROM_DEVICE);
			bd_dsc->data_dma_addr = 0;
			bd_dsc->skb->next = NULL;
			dev_kfree_skb_any(bd_dsc->skb);
			bd_dsc->skb = NULL;
		}
	} else {
		req->data_dma_addr = 0;
		if (req->skb)
			dev_kfree_skb_any(req->skb);
	}
	req->skb = NULL;

	return ret;
}

static int mtk_cldma_check_rx_req(struct cldma_drv_info *drv_info, struct rxq *rxq)
{
	struct rx_req *req = rxq->req_pool + rxq->free_idx;
	u64 curr_addr;
	int i;

	curr_addr = drv_info->drv_ops->cldma_get_rx_curr_addr(drv_info, rxq->rxqno);
	if (unlikely(!curr_addr))
		return -ENXIO;

	if (req->gpd_dma_addr == curr_addr)
		return -EAGAIN;
	for (i = 0; i < WAIT_HWO_ROUND; i++) {
		udelay(WAIT_HWO_TIME);
		if (!(READ_ONCE(req->gpd->rx_gpd.gpd_flags) & CLDMA_GPD_FLAG_HWO))
			break;
	}
	if (i == WAIT_HWO_ROUND) {
		dev_err((drv_info->mdev)->dev, "Failed to check HWO=0\n");
		return -EAGAIN;
	}

	return 0;
}

static bool mtk_cldma_rx_check_again(struct rxq *rxq)
{
	struct cldma_drv_info *drv_info;
	struct cldma_drv_ops *drv_ops;
	bool need_check_again = false;
	u32 state;
	int rxqno;

	drv_info = rxq->drv_info;
	drv_ops = drv_info->drv_ops;
	rxqno = rxq->rxqno;

	do {
		state = drv_ops->cldma_check_intr_status(drv_info, DIR_RX,
							 rxqno, QUEUE_XFER_DONE);
		if (state) {
			if (unlikely(state == LINK_ERROR_VAL))
				break;

			drv_ops->cldma_clr_intr_status(drv_info, DIR_RX,
						       rxqno, QUEUE_XFER_DONE);
			cond_resched();
			return true;
		}
	} while (need_check_again);

	return false;
}

/* Point the device at the GPD it should fill next and start the queue.
 * free_idx is owned by mtk_cldma_rx_done_work(), so this may only run
 * from that worker, at a point where every consumed GPD is re-armed.
 */
static void mtk_cldma_rxq_restart(struct cldma_drv_info *drv_info, struct rxq *rxq)
{
	struct cldma_drv_ops *drv_ops = drv_info->drv_ops;

	drv_ops->cldma_setup_start_addr(drv_info, DIR_RX, rxq->rxqno,
					rxq->req_pool[rxq->free_idx].gpd_dma_addr);
	drv_ops->cldma_start_queue(drv_info, DIR_RX, rxq->rxqno);
}

static void mtk_cldma_rx_done_work(struct work_struct *work)
{
	struct rx_req *req = NULL, *pre_req = NULL;
	struct rxq *rxq = container_of(work, struct rxq, rx_done_work);
	struct cldma_drv_info *drv_info;
	struct cldma_drv_ops *drv_ops;
	struct mtk_md_dev *mdev;
	struct sk_buff *rx_skb;
	int i, ret, idx, len_err;

	drv_info = rxq->drv_info;
	mdev = drv_info->mdev;
	drv_ops = drv_info->drv_ops;

again:
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + rxq->free_idx;
		if (!req->skb) {
			dev_err(mdev->dev,
				"Failed to get valid req cldma%d rxq%d req%d\n",
				drv_info->hw_id, rxq->rxqno, rxq->free_idx);
			goto out;
		}

		if (req->gpd->rx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO)
			break;

		dma_rmb(); /* read descriptor fields after HWO check */

		len_err = mtk_cldma_rx_skb_adjust(mdev, rxq, req);
		rx_skb = req->skb;
		req->skb = NULL;

		ret = mtk_cldma_reload_rx_skb(mdev, rxq, req);
		if (ret) {
			/* Alloc failed — recycle old buffer, drop packet.
			 * BD mode cannot recycle directly (BDP flag mismatch),
			 * so accept the stall and let reset recovery handle it.
			 */
			if (rxq->nr_bds) {
				dev_kfree_skb_any(rx_skb);
				goto out;
			}

			skb_trim(rx_skb, 0);
			req->skb = rx_skb;
			req->data_dma_addr = dma_map_single(mdev->dev,
							    rx_skb->data,
							    req->mtu,
							    DMA_FROM_DEVICE);
			if (dma_mapping_error(mdev->dev, req->data_dma_addr)) {
				req->data_dma_addr = 0;
				/* Keep rx_skb in req->skb for clean stall.
				 * HWO is not set — HW won't touch this slot.
				 * Queue stalls until modem reset recovery.
				 */
				goto out;
			} else {
				req->gpd->rx_gpd.data_buff_ptr_h =
					cpu_to_le32((u64)req->data_dma_addr >> 32);
				req->gpd->rx_gpd.data_buff_ptr_l =
					cpu_to_le32(req->data_dma_addr);
			}
		} else if (len_err) {
			dev_err_ratelimited(mdev->dev,
					    "Drop oversized packet on cldma%d rxq%d\n",
					    drv_info->hw_id, rxq->rxqno);
			dev_kfree_skb_any(rx_skb);
		} else {
			do {
				ret = rxq->rx_done(rx_skb, rxq->arg,
						   atomic_read(&rxq->need_exit) ? true : false);
				if (ret == -EAGAIN)
					usleep_range(1000, 2000);
			} while (ret == -EAGAIN);
		}

		wmb(); /* ensure addr set done before HWO setup done  */

		idx = rxq->free_idx == 0 ? rxq->nr_gpds - 1 : rxq->free_idx - 1;
		pre_req = rxq->req_pool + idx;
		pre_req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_HWO;
		rxq->free_idx = (rxq->free_idx + 1) % rxq->nr_gpds;
	}

	ret = mtk_cldma_check_rx_req(drv_info, rxq);
	if (!ret)
		goto again;
	else if (ret == -ENXIO)
		goto out;

	if (!atomic_read(&rxq->need_exit)) {
		if (atomic_xchg(&rxq->need_restart, 0))
			mtk_cldma_rxq_restart(drv_info, rxq);
		else
			drv_ops->cldma_resume_queue(drv_info, DIR_RX, rxq->rxqno);
	}

	if (mtk_cldma_rx_check_again(rxq))
		goto again;

out:
	drv_ops->cldma_unmask_intr(drv_info, DIR_RX, rxq->rxqno, QUEUE_XFER_DONE);
	drv_ops->cldma_clear_ip_busy(drv_info);
}

static int mtk_cldma_alloc_tx_bd(struct cldma_drv_info *drv_info, struct txq *txq,
				 struct tx_req *req)
{
	struct bd_dsc *bd_dsc, *last_bd_dsc = NULL;
	int i;

	req->bd_dsc_pool = kcalloc(txq->nr_bds, sizeof(*bd_dsc),
				   GFP_KERNEL);
	if (!req->bd_dsc_pool)
		return -ENOMEM;

	for (i = 0; i < txq->nr_bds; i++) {
		bd_dsc = req->bd_dsc_pool + i;
		bd_dsc->bd = dma_pool_zalloc(drv_info->bd_dma_pool, GFP_KERNEL,
					     &bd_dsc->bd_dma_addr);
		if (!bd_dsc->bd)
			return -ENOMEM;
		if (!last_bd_dsc) {
			req->gpd->tx_gpd.data_buff_ptr_h =
				cpu_to_le32((u64)(bd_dsc->bd_dma_addr) >> 32);
			req->gpd->tx_gpd.data_buff_ptr_l =
				cpu_to_le32(bd_dsc->bd_dma_addr);
		} else {
			last_bd_dsc->bd->tx_bd.next_bd_ptr_h =
				cpu_to_le32((u64)(bd_dsc->bd_dma_addr) >> 32);
			last_bd_dsc->bd->tx_bd.next_bd_ptr_l =
				cpu_to_le32(bd_dsc->bd_dma_addr);
		}
		last_bd_dsc = bd_dsc;
	}
	return 0;
}

static struct txq *mtk_cldma_txq_alloc(struct cldma_drv_info *drv_info, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_ops *drv_ops;
	struct mtk_ctrl_trans *trans;
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_md_dev *mdev;
	struct bd_dsc *bd_dsc;
	struct tx_req *next;
	struct tx_req *req;
	u16 tx_frag_size;
	struct txq *txq;
	int i, j, ret;

	mdev = drv_info->mdev;
	ctrl_blk = mdev->ctrl_blk;
	trans = ctrl_blk->ctrl_hw_priv;
	drv_ops = drv_info->drv_ops;

	txq = kzalloc_obj(*txq);
	if (!txq)
		return NULL;

	txq->que = radix_tree_lookup(&trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!txq->que))
		goto err_free_txq;
	txq->drv_info = drv_info;
	txq->txqno = txq->que->txqno;
	txq->nr_gpds = txq->que->tx_nr_gpds;
	atomic_set(&txq->req_budget, txq->que->tx_nr_gpds);
	spin_lock_init(&txq->ring_lock);
	txq->is_stopping = false;
	tx_frag_size = txq->que->tx_frag_size;
	if (txq->que->tx_mtu > tx_frag_size && tx_frag_size)
		txq->nr_bds = (txq->que->tx_mtu + tx_frag_size - 1) / tx_frag_size;

	txq->req_pool = kcalloc(txq->nr_gpds, sizeof(*req), GFP_KERNEL);
	if (!txq->req_pool)
		goto err_free_txq;

	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + i;
		req->mtu = txq->que->tx_mtu;
		req->frag_size = tx_frag_size;
		req->gpd = dma_pool_zalloc(drv_info->gpd_dma_pool, GFP_KERNEL, &req->gpd_dma_addr);
		if (!req->gpd)
			goto err_free_req;
		if (txq->nr_bds) {
			ret = mtk_cldma_alloc_tx_bd(drv_info, txq, req);
			if (ret)
				goto err_free_req;
			req->gpd->tx_gpd.gpd_flags |= CLDMA_GPD_FLAG_BDP;
		}
	}

	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + i;
		next = txq->req_pool + ((i + 1) % txq->nr_gpds);
		req->gpd->tx_gpd.gpd_flags |= CLDMA_GPD_FLAG_IOC;
		req->gpd->tx_gpd.next_gpd_ptr_h = cpu_to_le32((u64)(next->gpd_dma_addr) >> 32);
		req->gpd->tx_gpd.next_gpd_ptr_l = cpu_to_le32(next->gpd_dma_addr);
	}

	INIT_WORK(&txq->tx_done_work, mtk_cldma_tx_done_work);

	/* Publish the queue before unmasking its interrupts: an interrupt
	 * that fires in between must find a valid txq, or the sources it
	 * masks are never unmasked again.  The release pairs with the
	 * acquire load in the ISR.
	 */
	smp_store_release(&drv_info->txq[txq->txqno], txq);
	ret = drv_ops->cldma_stop_queue(drv_info, DIR_TX, txq->txqno);
	if (ret) {
		dev_warn(mdev->dev, "Failed to stop TX queue %d before alloc\n", txq->txqno);
		drv_info->txq[txq->txqno] = NULL;
		goto err_free_req;
	}
	txq->tx_started = false;
	drv_ops->cldma_setup_start_addr(drv_info, DIR_TX, txq->txqno,
					txq->req_pool[0].gpd_dma_addr);
	drv_ops->cldma_unmask_intr(drv_info, DIR_TX, txq->txqno, QUEUE_ERROR);
	drv_ops->cldma_unmask_intr(drv_info, DIR_TX, txq->txqno, QUEUE_XFER_DONE);

	return txq;

err_free_req:
	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + i;
		if (!req->gpd)
			break;
		if (req->bd_dsc_pool) {
			for (j = 0; j < txq->nr_bds; j++) {
				bd_dsc = req->bd_dsc_pool + j;
				if (!bd_dsc->bd)
					break;
				dma_pool_free(drv_info->bd_dma_pool, bd_dsc->bd,
					      bd_dsc->bd_dma_addr);
			}
			kfree(req->bd_dsc_pool);
		}
		dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
	}
	kfree(txq->req_pool);
err_free_txq:
	kfree(txq);
	return NULL;
}

/* cldma_drv_init() rewrites IP-global configuration (including the interrupt
 * mask) and cldma_drv_reset() wipes every queue of the instance, so all
 * queues still published in drv_info have to be re-armed, not only the one
 * that triggered the reset.  A queue already unpublished (NULL slot) is being
 * torn down and is deliberately left stopped.
 */
static void mtk_cldma_rearm_queues(struct cldma_drv_info *drv_info)
{
	struct cldma_drv_ops *drv_ops = drv_info->drv_ops;
	struct txq *txq;
	struct rxq *rxq;
	int i;

	drv_ops->cldma_drv_init(drv_info);

	for (i = 0; i < HW_QUEUE_NUM; i++) {
		txq = drv_info->txq[i];
		if (txq) {
			spin_lock(&txq->ring_lock);
			drv_ops->cldma_setup_start_addr(drv_info, DIR_TX, i,
							txq->req_pool[txq->free_idx].gpd_dma_addr);
			drv_ops->cldma_unmask_intr(drv_info, DIR_TX, i, QUEUE_ERROR);
			drv_ops->cldma_unmask_intr(drv_info, DIR_TX, i, QUEUE_XFER_DONE);
			if (READ_ONCE(txq->tx_started))
				drv_ops->cldma_start_queue(drv_info, DIR_TX, i);
			spin_unlock(&txq->ring_lock);
		}

		rxq = drv_info->rxq[i];
		if (rxq) {
			drv_ops->cldma_unmask_intr(drv_info, DIR_RX, i, QUEUE_ERROR);
			drv_ops->cldma_unmask_intr(drv_info, DIR_RX, i, QUEUE_XFER_DONE);
			/* free_idx belongs to rx_done_work, which may be halfway
			 * through a packet: let it program the start address
			 * once it reaches a consistent point.
			 */
			atomic_set(&rxq->need_restart, 1);
			queue_work(drv_info->wq, &rxq->rx_done_work);
		}
	}
}

static void mtk_cldma_txq_free(struct cldma_drv_info *drv_info, u32 txqno)
{
	struct cldma_drv_ops *drv_ops;
	struct mtk_md_dev *mdev;
	struct bd_dsc *bd_dsc;
	struct tx_req *req;
	struct txq *txq;
	struct trb *trb;
	int irq_id;
	int i, j, ret;

	mdev = drv_info->mdev;
	drv_ops = drv_info->drv_ops;

	txq = drv_info->txq[txqno];
	drv_info->txq[txqno] = NULL;
	/* stop HW tx transaction; -ENODEV means the link is dead, so the
	 * device cannot be walking the ring and the free may proceed.
	 */
	ret = drv_ops->cldma_stop_queue(drv_info, DIR_TX, txqno);
	if (ret == -ETIMEDOUT) {
		dev_err(mdev->dev, "TX queue %d stop timed out, resetting CLDMA%d\n",
			txqno, drv_info->hw_id);
		drv_ops->cldma_drv_reset(drv_info);
		ret = drv_ops->cldma_stop_queue(drv_info, DIR_TX, txqno);
		/* the reset took the whole instance down with this queue */
		mtk_cldma_rearm_queues(drv_info);
	}
	txq->tx_started = false;

	irq_id = mtk_pci_get_virq_id(mdev, drv_info->pci_ext_irq_id);
	synchronize_irq(irq_id);
	/* flush on-going work; the error worker may have loaded this txq
	 * before it was unpublished above, so it has to be retired too
	 */
	flush_work(&txq->tx_done_work);
	flush_work(&drv_info->err_work);
	drv_ops->cldma_mask_intr(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);
	drv_ops->cldma_mask_intr(drv_info, DIR_TX, txqno, QUEUE_ERROR);

	if (ret == -ETIMEDOUT) {
		/* Still a live DMA target: leak the ring rather than hand it
		 * back to the allocator.
		 */
		dev_err(mdev->dev, "TX queue %d cannot be stopped, leaking its ring\n",
			txqno);
		drv_info->ring_leaked = true;
		return;
	}

	/* Free tx req resource. No ring_lock is taken here: txq was already
	 * unpublished from drv_info->txq[] above, so no new producer can enter,
	 * and synchronize_irq() plus flush_work() have retired the consumer.
	 */
	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + txq->free_idx;
		if (req->skb && req->data_len) {
			if (!txq->nr_bds)
				dma_unmap_single(mdev->dev, req->data_dma_addr,
						 req->data_len, DMA_TO_DEVICE);
			for (j = 0; j < txq->nr_bds; j++) {
				bd_dsc = req->bd_dsc_pool + j;
				if (!bd_dsc->data_dma_addr)
					continue;
				dma_unmap_single(mdev->dev, bd_dsc->data_dma_addr,
						 bd_dsc->data_len, DMA_TO_DEVICE);
			}
			trb = (struct trb *)req->skb->cb;
			trb->status = -EPIPE;
			trb->trb_complete(req->skb);
		}
		for (j = 0; j < txq->nr_bds; j++) {
			bd_dsc = req->bd_dsc_pool + j;
			dma_pool_free(drv_info->bd_dma_pool, bd_dsc->bd,
				      bd_dsc->bd_dma_addr);
		}
		kfree(req->bd_dsc_pool);
		dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
		txq->free_idx = (txq->free_idx + 1) % txq->nr_gpds;
	}

	kfree(txq->req_pool);
	kfree(txq);
}

static int mtk_cldma_alloc_rx_bd(struct cldma_drv_info *drv_info, struct rx_req *req,
				 int nr_bds)
{
	struct bd_dsc *bd_dsc, *last_bd_dsc = NULL;
	struct sk_buff *tail = NULL;
	struct mtk_md_dev *mdev;
	u32 left_size;
	int ret;
	int i;

	mdev = drv_info->mdev;
	left_size = req->mtu;

	req->bd_dsc_pool = kcalloc(nr_bds, sizeof(*bd_dsc),
				   GFP_KERNEL);
	if (!req->bd_dsc_pool)
		return -ENOMEM;
	for (i = 0; i < nr_bds; i++) {
		bd_dsc = req->bd_dsc_pool + i;
		bd_dsc->bd = dma_pool_zalloc(drv_info->bd_dma_pool, GFP_KERNEL,
					     &bd_dsc->bd_dma_addr);
		if (!bd_dsc->bd)
			return -ENOMEM;

		bd_dsc->skb = __dev_alloc_skb(req->frag_size, GFP_KERNEL);
		if (!bd_dsc->skb)
			return -ENOMEM;
		bd_dsc->skb->next = NULL;
		bd_dsc->data_dma_addr =
			dma_map_single(mdev->dev, bd_dsc->skb->data,
				       req->frag_size, DMA_FROM_DEVICE);
		ret = dma_mapping_error(mdev->dev, bd_dsc->data_dma_addr);
		if (unlikely(ret))
			return -ENOMEM;

		bd_dsc->bd->rx_bd.data_buff_ptr_h =
			cpu_to_le32((u64)(bd_dsc->data_dma_addr) >> 32);
		bd_dsc->bd->rx_bd.data_buff_ptr_l =
			cpu_to_le32(bd_dsc->data_dma_addr);
		bd_dsc->bd->rx_bd.data_allow_len =
			cpu_to_le16(min(req->frag_size, left_size));
		left_size -= min(req->frag_size, left_size);
		if (!last_bd_dsc) {
			req->gpd->rx_gpd.data_buff_ptr_h =
				cpu_to_le32((u64)(bd_dsc->bd_dma_addr) >> 32);
			req->gpd->rx_gpd.data_buff_ptr_l =
				cpu_to_le32(bd_dsc->bd_dma_addr);
		} else {
			last_bd_dsc->bd->rx_bd.next_bd_ptr_h =
				cpu_to_le32((u64)(bd_dsc->bd_dma_addr) >> 32);
			last_bd_dsc->bd->rx_bd.next_bd_ptr_l =
				cpu_to_le32(bd_dsc->bd_dma_addr);
		}
		last_bd_dsc = bd_dsc;
		if (tail) {
			tail->next = bd_dsc->skb;
			tail = bd_dsc->skb;
			continue;
		}
		if (!req->skb) {
			req->skb = bd_dsc->skb;
		} else {
			skb_shinfo(req->skb)->frag_list = bd_dsc->skb;
			tail = bd_dsc->skb;
		}
	}
	last_bd_dsc->bd->rx_bd.bd_flags |= CLDMA_BD_FLAG_EOL;
	return 0;
}

static void mtk_cldma_rxq_alloc_cancel(struct cldma_drv_info *drv_info, struct rx_req *req,
				       int nr_bds)
{
	struct mtk_md_dev *mdev;
	struct bd_dsc *bd_dsc;
	int i;

	mdev = drv_info->mdev;

	if (nr_bds) {
		if (req->skb)
			skb_shinfo(req->skb)->frag_list = NULL;
		if (req->bd_dsc_pool) {
			for (i = 0; i < nr_bds; i++) {
				bd_dsc = req->bd_dsc_pool + i;
				if (!bd_dsc->bd)
					break;
				if (bd_dsc->skb) {
					if (!dma_mapping_error(mdev->dev, bd_dsc->data_dma_addr))
						dma_unmap_single(mdev->dev, bd_dsc->data_dma_addr,
								 req->frag_size, DMA_FROM_DEVICE);
					bd_dsc->data_dma_addr = 0;
					bd_dsc->skb->next = NULL;
					dev_kfree_skb_any(bd_dsc->skb);
				}
				dma_pool_free(drv_info->bd_dma_pool, bd_dsc->bd,
					      bd_dsc->bd_dma_addr);
			}
			kfree(req->bd_dsc_pool);
		}
	} else {
		if (req->skb) {
			if (!dma_mapping_error(mdev->dev, req->data_dma_addr))
				dma_unmap_single(mdev->dev, req->data_dma_addr,
						 req->mtu, DMA_FROM_DEVICE);
			req->data_dma_addr = 0;
			dev_kfree_skb_any(req->skb);
		}
	}
	dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
}

static struct rxq *mtk_cldma_rxq_alloc(struct cldma_drv_info *drv_info, struct sk_buff *skb)
{
	struct trb_open_priv *trb_open_priv = (struct trb_open_priv *)skb->data;
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_ops *drv_ops;
	struct mtk_ctrl_trans *trans;
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_md_dev *mdev;
	struct rx_req *next;
	struct rx_req *req;
	u16 rx_frag_size;
	struct rxq *rxq;
	int ret;
	int i;

	mdev = drv_info->mdev;
	ctrl_blk = mdev->ctrl_blk;
	trans = ctrl_blk->ctrl_hw_priv;
	drv_ops = drv_info->drv_ops;

	rxq = kzalloc_obj(*rxq);
	if (!rxq)
		return NULL;

	rxq->que = radix_tree_lookup(&trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!rxq->que))
		goto err_free_rxq;
	rxq->drv_info = drv_info;
	rxq->rxqno = rxq->que->rxqno;
	if (rxq->que->rx_nr_gpds < MIN_GPD_NUM) {
		dev_err(mdev->dev,
			"Failed to alloc cldma%d rxq%d due to gpd number < 2\n",
			drv_info->hw_id, rxq->rxqno);
		goto err_free_rxq;
	}
	rxq->nr_gpds = rxq->que->rx_nr_gpds;
	rxq->arg = trb->priv;
	rxq->rx_done = trb_open_priv->rx_done;
	atomic_set(&rxq->need_exit, 0);
	atomic_set(&rxq->need_restart, 0);
	rx_frag_size = rxq->que->rx_frag_size;
	if (rxq->que->rx_mtu > rx_frag_size && rx_frag_size)
		rxq->nr_bds = (rxq->que->rx_mtu + rx_frag_size - 1) / rx_frag_size;

	rxq->req_pool = kcalloc(rxq->nr_gpds, sizeof(*req), GFP_KERNEL);
	if (!rxq->req_pool)
		goto err_free_rxq;

	/* setup rx request */
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + i;
		req->mtu = rxq->que->rx_mtu;
		req->frag_size = rx_frag_size;
		req->gpd = dma_pool_zalloc(drv_info->gpd_dma_pool, GFP_KERNEL, &req->gpd_dma_addr);
		if (!req->gpd)
			goto err_free_req;
		if (rxq->nr_bds) {
			ret = mtk_cldma_alloc_rx_bd(drv_info, req, rxq->nr_bds);
			if (ret)
				goto err_free_req;
			req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_BDP;
		} else {
			req->skb = __dev_alloc_skb(req->mtu, GFP_KERNEL);
			if (!req->skb)
				goto err_free_req;
			req->data_dma_addr = dma_map_single(mdev->dev, req->skb->data,
							    req->mtu, DMA_FROM_DEVICE);
			ret = dma_mapping_error(mdev->dev, req->data_dma_addr);
			if (unlikely(ret))
				goto err_free_req;
		}
	}

	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + i;
		next = rxq->req_pool + ((i + 1) % rxq->nr_gpds);
		req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_IOC;
		req->gpd->rx_gpd.data_allow_len = cpu_to_le16(req->mtu);
		req->gpd->rx_gpd.next_gpd_ptr_h = cpu_to_le32((u64)(next->gpd_dma_addr) >> 32);
		req->gpd->rx_gpd.next_gpd_ptr_l = cpu_to_le32(next->gpd_dma_addr);
		if (!rxq->nr_bds) {
			req->gpd->rx_gpd.data_buff_ptr_h =
				cpu_to_le32((u64)(req->data_dma_addr) >> 32);
			req->gpd->rx_gpd.data_buff_ptr_l = cpu_to_le32(req->data_dma_addr);
		}
		if (i != rxq->nr_gpds - 1)
			req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_HWO;
	}

	INIT_WORK(&rxq->rx_done_work, mtk_cldma_rx_done_work);

	/* Pairs with the acquire load in the ISR, as for txq above. */
	smp_store_release(&drv_info->rxq[rxq->rxqno], rxq);
	ret = drv_ops->cldma_stop_queue(drv_info, DIR_RX, rxq->rxqno);
	if (ret) {
		dev_warn(mdev->dev, "Failed to stop RX queue %d before alloc\n", rxq->rxqno);
		drv_info->rxq[rxq->rxqno] = NULL;
		goto err_free_req;
	}
	drv_ops->cldma_setup_start_addr(drv_info, DIR_RX,
					rxq->rxqno, rxq->req_pool[0].gpd_dma_addr);
	drv_ops->cldma_start_queue(drv_info, DIR_RX, rxq->rxqno);
	drv_ops->cldma_unmask_intr(drv_info, DIR_RX, rxq->rxqno, QUEUE_ERROR);
	drv_ops->cldma_unmask_intr(drv_info, DIR_RX, rxq->rxqno, QUEUE_XFER_DONE);

	return rxq;

err_free_req:
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + i;
		if (!req->gpd)
			break;
		mtk_cldma_rxq_alloc_cancel(drv_info, req, rxq->nr_bds);
	}

	kfree(rxq->req_pool);
err_free_rxq:
	kfree(rxq);
	return NULL;
}

static void mtk_cldma_rxq_free(struct cldma_drv_info *drv_info, u32 rxqno)
{
	struct cldma_drv_ops *drv_ops;
	struct mtk_md_dev *mdev;
	struct bd_dsc *bd_dsc;
	struct rx_req *req;
	struct rxq *rxq;
	int irq_id;
	int i, j, ret;

	mdev = drv_info->mdev;
	drv_ops = drv_info->drv_ops;

	rxq = drv_info->rxq[rxqno];
	drv_info->rxq[rxqno] = NULL;

	/* stop HW rx transaction; -ENODEV means the link is dead, so the
	 * device cannot be walking the ring and the free may proceed.
	 */
	atomic_set(&rxq->need_exit, 1);
	ret = drv_ops->cldma_stop_queue(drv_info, DIR_RX, rxqno);
	if (ret == -ETIMEDOUT) {
		dev_err(mdev->dev, "RX queue %d stop timed out, resetting CLDMA%d\n",
			rxqno, drv_info->hw_id);
		drv_ops->cldma_drv_reset(drv_info);
		ret = drv_ops->cldma_stop_queue(drv_info, DIR_RX, rxqno);
		/* the reset took the whole instance down with this queue */
		mtk_cldma_rearm_queues(drv_info);
	}

	irq_id = mtk_pci_get_virq_id(mdev, drv_info->pci_ext_irq_id);
	synchronize_irq(irq_id);
	/* flush on-going work; the error worker may still be about to stop
	 * this queue number, which a later allocation could already reuse
	 */
	flush_work(&rxq->rx_done_work);
	flush_work(&drv_info->err_work);
	/* mask L2 RX interrupt again to avoid race condition causing use-after-free issue */
	drv_ops->cldma_mask_intr(drv_info, DIR_RX, rxqno, QUEUE_XFER_DONE);
	drv_ops->cldma_mask_intr(drv_info, DIR_RX, rxqno, QUEUE_ERROR);

	if (ret == -ETIMEDOUT) {
		/* Still a live DMA target: leak the ring rather than hand it
		 * back to the allocator.
		 */
		dev_err(mdev->dev, "RX queue %d cannot be stopped, leaking its ring\n",
			rxqno);
		drv_info->ring_leaked = true;
		return;
	}

	/* free rx req resource */
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + rxq->free_idx;
		if (!(req->gpd->rx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO) &&
		    le16_to_cpu(req->gpd->rx_gpd.data_recv_len)) {
			if (!mtk_cldma_rx_skb_adjust(mdev, rxq, req)) {
				rxq->rx_done(req->skb, rxq->arg, true);
				req->skb = NULL;
			}
		}
		if (req->skb) {
			if (!rxq->nr_bds) {
				if (req->data_dma_addr)
					dma_unmap_single(mdev->dev, req->data_dma_addr,
							 req->mtu, DMA_FROM_DEVICE);
				dev_kfree_skb_any(req->skb);
			} else if (req->bd_dsc_pool[0].skb) {
				/* The head skb aliases bd_dsc_pool[0].skb and the
				 * frag_list chain aliases the other BD skbs: break
				 * the aliases and let the BD walk below free every
				 * skb exactly once, as rxq_alloc_cancel() does.
				 */
				skb_shinfo(req->skb)->frag_list = NULL;
			} else {
				/* The BD skbs are already detached, the head owns
				 * the whole chain through its frag_list.
				 */
				dev_kfree_skb_any(req->skb);
			}
			req->skb = NULL;
		}
		for (j = 0; j < rxq->nr_bds; j++) {
			bd_dsc = req->bd_dsc_pool + j;
			if (bd_dsc->skb) {
				if (bd_dsc->data_dma_addr)
					dma_unmap_single(mdev->dev, bd_dsc->data_dma_addr,
							 req->frag_size, DMA_FROM_DEVICE);
				bd_dsc->skb->next = NULL;
				dev_kfree_skb_any(bd_dsc->skb);
			}
			dma_pool_free(drv_info->bd_dma_pool,
				      bd_dsc->bd, bd_dsc->bd_dma_addr);
		}
		kfree(req->bd_dsc_pool);
		dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
		rxq->free_idx = (rxq->free_idx + 1) % rxq->nr_gpds;
	}

	kfree(rxq->req_pool);
	kfree(rxq);
}

/* The device reported a zero TX start address: it lost its queue state. */
static int mtk_cldma_hw_recovery(struct cldma_drv_info *drv_info, u32 qno)
{
	struct cldma_drv_ops *drv_ops = drv_info->drv_ops;
	u64 val;

	dev_err(drv_info->mdev->dev,
		"CLDMA%d lost its queue state, re-initializing\n",
		drv_info->hw_id);

	mtk_cldma_rearm_queues(drv_info);

	val = drv_ops->cldma_get_tx_start_addr(drv_info, qno);
	if (!val || val == U64_MAX)
		return -EIO;

	return 0;
}

static int mtk_cldma_dev_exit(struct cldma_dev *cd, int hif_id)
{
	struct cldma_drv_info *drv_info;
	struct mtk_md_dev *mdev;
	int virq_id;
	int i;

	if (!cd || hif_id >= NR_CLDMA)
		return -EINVAL;

	if (!cd->cldma_drv_info[hif_id])
		return 0;

	/* free cldma descriptor */
	drv_info = cd->cldma_drv_info[hif_id];
	mdev = cd->trans->mdev;
	virq_id = mtk_pci_get_virq_id(mdev, drv_info->pci_ext_irq_id);
	/* mask first so no new interrupt can fire, then wait out any
	 * in-flight handler before tearing the registration down
	 */
	mtk_pci_mask_irq(mdev, drv_info->pci_ext_irq_id);
	synchronize_irq(virq_id);
	mtk_pci_unregister_irq(mdev, drv_info->pci_ext_irq_id);
	for (i = 0; i < HW_QUEUE_NUM; i++) {
		if (drv_info->txq[i])
			mtk_cldma_txq_free(drv_info, drv_info->txq[i]->txqno);
		if (drv_info->rxq[i])
			mtk_cldma_rxq_free(drv_info, drv_info->rxq[i]->rxqno);
	}

	flush_workqueue(drv_info->wq);
	destroy_workqueue(drv_info->wq);

	/* quiesce the IP before releasing descriptor memory: disable its
	 * interrupt output and reset it, so it cannot touch the rings again
	 */
	mtk_pci_write32(mdev, drv_info->base_addr + drv_info->hw_regs->reg_cldma_int_mask,
			LINK_ERROR_VAL);
	drv_info->drv_ops->cldma_drv_reset(drv_info);

	if (drv_info->ring_leaked) {
		/* A ring is leaked and its descriptors live in these pools:
		 * the device may still master DMA into them, so handing them
		 * back to the allocator would open a use-after-free window.
		 */
		dev_err(mdev->dev, "CLDMA%d rings leaked, leaking DMA pools too\n",
			drv_info->hw_id);
	} else {
		dma_pool_destroy(drv_info->bd_dma_pool);
		dma_pool_destroy(drv_info->gpd_dma_pool);
	}

	cd->cldma_drv_info[hif_id] = NULL;
	kfree(drv_info);

	return 0;
}

static int mtk_cldma_start_xfer(struct cldma_drv_info *drv_info, u32 qno)
{
	struct cldma_drv_ops *drv_ops;
	struct txq *txq;
	u64 val;
	int ret;

	txq = drv_info->txq[qno];
	drv_ops = drv_info->drv_ops;

	val = drv_ops->cldma_get_tx_start_addr(drv_info, qno);
	if (unlikely(val == U64_MAX))
		return -EIO;

	if (unlikely(!val)) {
		ret = mtk_cldma_hw_recovery(drv_info, qno);
		if (ret)
			return ret;
	}

	/* Hold ring_lock across programming and kicking the queue so the
	 * start address given to the device is the one free_idx still
	 * names; tx_done_work advances free_idx under the same lock.
	 */
	spin_lock(&txq->ring_lock);
	if (unlikely(!READ_ONCE(txq->tx_started))) {
		drv_ops->cldma_setup_start_addr(drv_info, DIR_TX, qno,
						txq->req_pool[txq->free_idx].gpd_dma_addr);
		drv_ops->cldma_start_queue(drv_info, DIR_TX, qno);
		WRITE_ONCE(txq->tx_started, true);
	} else {
		drv_ops->cldma_resume_queue(drv_info, DIR_TX, qno);
	}
	spin_unlock(&txq->ring_lock);

	return 0;
}

int mtk_cldma_init(struct mtk_ctrl_trans *trans)
{
	struct cldma_dev *cd;

	cd = kzalloc_obj(*cd);
	if (!cd)
		return -ENOMEM;

	cd->trans = trans;
	trans->dev = cd;

	return 0;
}

void mtk_cldma_exit(struct mtk_ctrl_trans *trans)
{
	struct cldma_dev *cd = trans->dev;
	int i;

	if (!cd)
		return;

	/* Latch-and-clear up front: the caller holds trans->submit_lock, so
	 * publishing the NULL here makes any later submit path bail out in
	 * mtk_cldma_get_tx_budget() instead of walking freed queues.
	 */
	trans->dev = NULL;

	for (i = 0; i < NR_CLDMA; i++)
		mtk_cldma_dev_exit(cd, i);

	kfree(cd);
}

static int mtk_cldma_open(struct cldma_dev *cd, struct sk_buff *skb)
{
	struct trb_open_priv *trb_open_priv = (struct trb_open_priv *)skb->data;
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_info *drv_info;
	struct queue_info *que;
	struct txq *txq;
	struct rxq *rxq;
	int ret = 0;

	que = radix_tree_lookup(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!que)) {
		trb->status = -EINVAL;
		trb->trb_complete(skb);
		return -EINVAL;
	}
	drv_info = cd->cldma_drv_info[que->hif_id];
	if (!drv_info) {
		ret = -EIO;
		goto out;
	}

	if (que->tx_mtu == 0 || que->rx_mtu == 0) {
		dev_err((cd->trans->mdev)->dev,
			"Failed to enable cldma%d txq%d rxq%d due to wrong mtu\n",
			drv_info->hw_id, que->txqno, que->rxqno);
		ret = -EINVAL;
		goto out;
	}

	trb_open_priv->tx_mtu = que->tx_mtu;
	trb_open_priv->rx_mtu = que->rx_mtu;
	trb_open_priv->tx_frag_size = que->tx_frag_size;
	trb_open_priv->rx_frag_size = que->rx_frag_size;

	if (drv_info->txq[que->txqno] || drv_info->rxq[que->rxqno]) {
		ret = -EBUSY;
		goto out;
	}

	txq = mtk_cldma_txq_alloc(drv_info, skb);
	if (!txq) {
		ret = -ENOMEM;
		goto out;
	}

	rxq = mtk_cldma_rxq_alloc(drv_info, skb);
	if (!rxq) {
		ret = -ENOMEM;
		mtk_cldma_txq_free(drv_info, txq->txqno);
		goto out;
	}

out:
	if (ret)
		cd->trans->usr_cnt[que->hif_id][que->txqno]--;

	trb->status = ret;
	trb->trb_complete(skb);

	return ret;
}

/* Complete every submitted-but-unkicked request with an error so no TRB
 * is stranded in the ring when the doorbell cannot be rung.
 */
static void mtk_cldma_txq_flush(struct cldma_drv_info *drv_info,
				struct txq *txq, int err)
{
	struct mtk_ctrl_trans *trans = drv_info->cd->trans;
	int hif_id = drv_info->hif_id;
	u32 txqno = txq->txqno;
	struct sk_buff *skb;
	struct tx_req *req;
	bool was_starved;
	struct trb *trb;
	int i;

	for (i = 0; i < txq->nr_gpds; i++) {
		spin_lock(&txq->ring_lock);

		req = txq->req_pool + txq->free_idx;
		if (!req->skb) {
			spin_unlock(&txq->ring_lock);
			break;
		}

		req->gpd->tx_gpd.gpd_flags &= ~CLDMA_GPD_FLAG_HWO;

		if (txq->nr_bds)
			mtk_cldma_clr_bd_dsc(drv_info, req->bd_dsc_pool, txq->nr_bds);
		else
			dma_unmap_single(drv_info->mdev->dev, req->data_dma_addr,
					 req->data_len, DMA_TO_DEVICE);

		skb = req->skb;
		req->data_dma_addr = 0;
		req->data_len = 0;
		req->skb = NULL;

		txq->free_idx = (txq->free_idx + 1) % txq->nr_gpds;
		was_starved = atomic_fetch_inc(&txq->req_budget) == NO_BUDGET;

		spin_unlock(&txq->ring_lock);

		trb = (struct trb *)skb->cb;
		trb->status = err;
		trb->trb_complete(skb);

		if (was_starved)
			wake_up(&trans->trb_srv[trans->srv_cfg[hif_id][txqno]]->trb_waitq);
	}
}

/* Handle QUEUE_ERROR interrupts out of atomic context: stop the errored
 * queues so the device stops walking their rings, and complete pending TX
 * requests with an error so the failure is reported upward instead of
 * being silently logged.
 */
static void mtk_cldma_err_work(struct work_struct *work)
{
	struct cldma_drv_info *drv_info = container_of(work, struct cldma_drv_info, err_work);
	u32 tx_err, rx_err;
	struct txq *txq;
	struct rxq *rxq;
	int i, ret;

	tx_err = atomic_xchg(&drv_info->tx_err_qs, 0);
	rx_err = atomic_xchg(&drv_info->rx_err_qs, 0);

	for (i = 0; i < HW_QUEUE_NUM; i++) {
		if (tx_err & BIT(i)) {
			/* pairs with smp_store_release() in txq_alloc */
			txq = smp_load_acquire(&drv_info->txq[i]);
			if (!txq)
				continue;
			ret = drv_info->drv_ops->cldma_stop_queue(drv_info, DIR_TX, i);
			if (ret) {
				/* the device may still be walking the ring:
				 * unmapping its buffers here would leave it
				 * writing into unmapped memory
				 */
				dev_err(drv_info->mdev->dev,
					"TX queue %d stop failed (%d), keeping its requests\n",
					i, ret);
			} else {
				spin_lock(&txq->ring_lock);
				WRITE_ONCE(txq->tx_started, false);
				spin_unlock(&txq->ring_lock);
				mtk_cldma_txq_flush(drv_info, txq, -EPIPE);
			}
		}
		if (rx_err & BIT(i)) {
			/* pairs with smp_store_release() in rxq_alloc */
			rxq = smp_load_acquire(&drv_info->rxq[i]);
			if (!rxq)
				continue;
			drv_info->drv_ops->cldma_stop_queue(drv_info, DIR_RX, i);
		}
	}
}

static int mtk_cldma_tx(struct cldma_dev *cd, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_info *drv_info;
	struct mtk_md_dev *mdev;
	struct queue_info *que;
	struct txq *txq;
	int ret;

	que = radix_tree_lookup(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!que))
		return -EPIPE;
	drv_info = cd->cldma_drv_info[que->hif_id];
	if (unlikely(!drv_info))
		return -EPIPE;
	txq = drv_info->txq[que->txqno];
	if (unlikely(!txq) || txq->is_stopping)
		return -EPIPE;

	mdev = drv_info->mdev;

	ret = mtk_cldma_start_xfer(drv_info, que->txqno);
	if (unlikely(ret)) {
		dev_err(mdev->dev, "Failed to trigger cldma tx\n");
		mtk_cldma_txq_flush(drv_info, txq, ret);
	}

	return ret;
}

static int mtk_cldma_close(struct cldma_dev *cd, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_info *drv_info;
	struct queue_info *que;

	que = radix_tree_lookup(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!que)) {
		trb->status = -EPIPE;
		trb->trb_complete(skb);
		return -EPIPE;
	}
	drv_info = cd->cldma_drv_info[que->hif_id];
	if (unlikely(!drv_info)) {
		trb->status = -EPIPE;
		trb->trb_complete(skb);
		return -EPIPE;
	}

	if (drv_info->txq[que->txqno])
		mtk_cldma_txq_free(drv_info, que->txqno);
	if (drv_info->rxq[que->rxqno])
		mtk_cldma_rxq_free(drv_info, que->rxqno);

	trb->status = 0;
	trb->trb_complete(skb);

	return 0;
}

static int mtk_cldma_txbuf_set(struct cldma_drv_info *drv_info, struct sk_buff *skb,
			       struct tx_req *req, int nr_bds)
{
	struct sk_buff *curr_skb, *next_skb;
	struct mtk_md_dev *mdev;
	struct bd_dsc *bd_dsc;
	int ret;
	int i;

	mdev = drv_info->mdev;

	if (nr_bds) {
		bd_dsc = req->bd_dsc_pool;
		curr_skb = skb;
		for (i = 0; i < nr_bds && curr_skb; i++) {
			bd_dsc = req->bd_dsc_pool + i;
			if (req->bd_dsc_pool == bd_dsc) {
				bd_dsc->data_len = skb->len - skb->data_len;
				next_skb = skb_shinfo(skb)->frag_list;
			} else {
				bd_dsc->data_len = curr_skb->len;
				next_skb = curr_skb->next;
			}
			bd_dsc->data_dma_addr = dma_map_single(mdev->dev, curr_skb->data,
							       bd_dsc->data_len, DMA_TO_DEVICE);
			ret = dma_mapping_error(mdev->dev, bd_dsc->data_dma_addr);
			if (unlikely(ret))
				goto err_unmap_buffer;

			bd_dsc->bd->tx_bd.data_buff_ptr_h =
				cpu_to_le32((u64)(bd_dsc->data_dma_addr) >> 32);
			bd_dsc->bd->tx_bd.data_buff_ptr_l = cpu_to_le32(bd_dsc->data_dma_addr);
			bd_dsc->bd->tx_bd.data_buffer_len = cpu_to_le16(bd_dsc->data_len);
			curr_skb = next_skb;
		}
		bd_dsc->bd->tx_bd.bd_flags = CLDMA_BD_FLAG_EOL;
	} else {
		/* Non-BD mode maps only the linear area; a nonlinear SKB
		 * here would be silently truncated to skb_headlen().
		 */
		if (WARN_ON_ONCE(skb_is_nonlinear(skb)))
			return -EINVAL;

		req->data_dma_addr = dma_map_single(mdev->dev, skb->data,
						    skb_headlen(skb), DMA_TO_DEVICE);
		ret = dma_mapping_error(mdev->dev, req->data_dma_addr);
		if (unlikely(ret)) {
			req->data_dma_addr = 0;
			goto err_exit;
		}

		req->gpd->tx_gpd.data_buff_ptr_h = cpu_to_le32((u64)(req->data_dma_addr) >> 32);
		req->gpd->tx_gpd.data_buff_ptr_l = cpu_to_le32(req->data_dma_addr);
	}

	return 0;

err_unmap_buffer:
	for (i = 0; i < nr_bds; i++) {
		bd_dsc = req->bd_dsc_pool + i;
		if (dma_mapping_error(mdev->dev, bd_dsc->data_dma_addr)) {
			bd_dsc->data_dma_addr = 0;
			break;
		}
		dma_unmap_single(mdev->dev, bd_dsc->data_dma_addr,
				 bd_dsc->data_len, DMA_TO_DEVICE);
		bd_dsc->data_dma_addr = 0;
	}
err_exit:
	dev_err_ratelimited(mdev->dev, "Failed to map dma! error:%d\n", ret);
	return -ENOMEM;
}

int mtk_cldma_submit_tx(void *dev, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_info *drv_info;
	struct cldma_dev *cd = dev;
	struct queue_info *que;
	struct tx_req *req;
	struct txq *txq;
	int ret;

	/* the CLDMA device is unpublished before it is freed, so a submitter
	 * that raced the teardown lands here with a NULL dev
	 */
	if (unlikely(!cd))
		return -EINVAL;

	que = radix_tree_lookup(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!que))
		return -EINVAL;
	drv_info = cd->cldma_drv_info[que->hif_id];
	if (unlikely(!drv_info))
		return -EINVAL;

	txq = drv_info->txq[que->txqno];
	if (unlikely(!txq))
		return -EINVAL;

	spin_lock(&txq->ring_lock);

	if (!atomic_read(&txq->req_budget)) {
		spin_unlock(&txq->ring_lock);
		return -EAGAIN;
	}

	req = txq->req_pool + txq->wr_idx;
	req->gpd->tx_gpd.debug_id = 0x01;
	ret = mtk_cldma_txbuf_set(drv_info, skb, req, txq->nr_bds);
	if (ret) {
		spin_unlock(&txq->ring_lock);
		return ret;
	}

	req->gpd->tx_gpd.data_buff_len = cpu_to_le16(skb->len);

	req->data_len = skb->len;
	req->skb = skb;

	dma_wmb(); /* ensure req and data msg set done before HWO setup */

	req->gpd->tx_gpd.gpd_flags |= CLDMA_GPD_FLAG_HWO;

	txq->wr_idx = (txq->wr_idx + 1) % txq->nr_gpds;
	atomic_dec(&txq->req_budget);

	spin_unlock(&txq->ring_lock);

	return 0;
}

int mtk_cldma_get_tx_budget(void *dev, enum mtk_hif_id hif_id, u32 qno)
{
	struct cldma_drv_info *drv_info;
	struct cldma_dev *cd = dev;
	struct txq *txq;

	if (unlikely(hif_id >= NR_CLDMA || qno >= HW_QUE_NUM || !cd))
		return -EINVAL;

	drv_info = cd->cldma_drv_info[hif_id];
	if (!drv_info)
		return -EINVAL;
	txq = drv_info->txq[qno];
	if (!txq)
		return -EINVAL;
	return atomic_read(&txq->req_budget);
}

static int (*trb_act_tbl[TRB_CMD_MAX])(struct cldma_dev *cd, struct sk_buff *skb) = {
	[TRB_CMD_ENABLE] = mtk_cldma_open,
	[TRB_CMD_TX] = mtk_cldma_tx,
	[TRB_CMD_DISABLE] = mtk_cldma_close,
};

int mtk_cldma_trb_process(void *dev, struct sk_buff *skb)
{
	struct cldma_dev *cd;
	struct trb *trb;

	if (!dev || !skb)
		return -EINVAL;

	cd = (struct cldma_dev *)dev;
	trb = (struct trb *)skb->cb;

	if (!(trb->cmd > TRB_CMD_MIN && trb->cmd < TRB_CMD_STOP))
		return -EINVAL;

	return trb_act_tbl[trb->cmd](cd, skb);
}

void mtk_cldma_fsm_state_listener(struct mtk_fsm_param *param, struct mtk_ctrl_trans *trans)
{
	struct cldma_dev *cd = trans->dev;
	int ret = 0;

	switch (param->to) {
	case FSM_STATE_BOOTUP:
		if (param->fsm_flag & FSM_F_SAP_HS_START)
			ret = mtk_cldma_dev_init(cd, CLDMA0);
		else if (param->fsm_flag & FSM_F_MD_HS_START)
			ret = mtk_cldma_dev_init(cd, CLDMA1);
		if (ret) {
			dev_err(trans->mdev->dev, "Failed to init CLDMA: %d\n", ret);
			mtk_fsm_hif_err_record(trans->mdev, ret);
		}
		break;
	default:
		break;
	}
}

int mtk_cldma_check_ch_cfg(void *dev, struct queue_info *que)
{
	struct cldma_drv_info *drv_info;
	struct cldma_dev *cd = dev;
	struct mtk_md_dev *mdev;
	struct txq *txq;
	struct rxq *rxq;

	mdev = cd->trans->mdev;
	drv_info = cd->cldma_drv_info[que->hif_id];

	if (!drv_info) {
		dev_err(mdev->dev, "CLDMA%d has not been initialized\n",
			mtk_cldma_hw_id_tbl[que->hif_id]);
		return -EINVAL;
	}

	txq = drv_info->txq[que->txqno];
	rxq = drv_info->rxq[que->rxqno];
	if (!txq || !rxq) {
		dev_err(mdev->dev,
			"CLDMA%d txq%d rxq%d has not been enabled\n",
			mtk_cldma_hw_id_tbl[que->hif_id], que->txqno, que->rxqno);
		return -EINVAL;
	}

	if (que->tx_mtu != txq->que->tx_mtu || que->rx_mtu != rxq->que->rx_mtu) {
		dev_err(mdev->dev,
			"Channel:%08x tx_mtu:%08x rx_mtu:%08x do not match ch cfg\n",
			que->tx_chl, que->tx_mtu, que->rx_mtu);
		return -EINVAL;
	}

	return 0;
}
