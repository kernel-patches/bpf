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

#define WAIT_HWO_ROUND		(10)
#define WAIT_HWO_TIME		(5)
#define NO_BUDGET		(0)

static const int mtk_cldma_hw_id_tbl[NR_CLDMA] = {
	[CLDMA0] = CLDMA0_HW_ID,
	[CLDMA1] = CLDMA1_HW_ID,
};

static void mtk_cldma_tx_done_work(struct work_struct *work)
{
	struct txq *txq = container_of(work, struct txq, tx_done_work);
	struct cldma_drv_info *drv_info;
	struct mtk_ctrl_trans *trans;
	struct mtk_md_dev *mdev;
	struct sk_buff *skb;
	struct trb_srv *srv;
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

		/* The service may already have been torn down; completing the
		 * TRB is still correct, there is just nobody left to wake.
		 */
		srv = trans->trb_srv[trans->srv_cfg[hif_id][txqno]];
		if (was_starved && srv)
			wake_up(&srv->trb_waitq);
	}

	state = mtk_cldma_check_intr_status(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);
	if (state) {
		if (unlikely(state == LINK_ERROR_VAL))
			goto out;

		mtk_cldma_clr_intr_status(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);

		cond_resched();

		goto again;
	}

out:
	mtk_cldma_unmask_intr(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);
}

/* data_recv_len is read back from a buffer the device writes, so it is
 * clamped against req->mtu before it reaches skb_put().
 *
 * Returns -EPROTO when the device over-reports so the caller drops the packet
 * instead of delivering a malformed skb.
 */
static int mtk_cldma_rx_skb_adjust(struct mtk_md_dev *mdev, struct rx_req *req)
{
	u32 recv_len;
	int ret = 0;

	if (req->data_dma_addr) {
		dma_unmap_single(mdev->dev, req->data_dma_addr,
				 req->mtu, DMA_FROM_DEVICE);
		req->data_dma_addr = 0;
	}
	recv_len = le16_to_cpu(req->gpd->rx_gpd.data_recv_len);
	if (recv_len > req->mtu) {
		ret = -EPROTO;
		recv_len = req->mtu;
	}
	req->skb->len = 0;
	skb_reset_tail_pointer(req->skb);
	skb_put(req->skb, recv_len);

	req->gpd->rx_gpd.data_recv_len = 0;

	return ret;
}

static int mtk_cldma_reload_rx_skb(struct mtk_md_dev *mdev, struct rx_req *req)
{
	int ret;

	req->skb = __dev_alloc_skb(req->mtu, GFP_KERNEL);
	if (!req->skb)
		return -ENOMEM;

	req->data_dma_addr = dma_map_single(mdev->dev, req->skb->data,
					    req->mtu, DMA_FROM_DEVICE);
	ret = dma_mapping_error(mdev->dev, req->data_dma_addr);
	if (unlikely(ret)) {
		dev_warn_ratelimited(mdev->dev, "Failed to map SKB data\n");
		req->data_dma_addr = 0;
		dev_kfree_skb_any(req->skb);
		req->skb = NULL;
		return -EFAULT;
	}
	req->gpd->rx_gpd.data_buff_ptr_h = cpu_to_le32((u64)req->data_dma_addr >> 32);
	req->gpd->rx_gpd.data_buff_ptr_l = cpu_to_le32(req->data_dma_addr);

	return 0;
}

static int mtk_cldma_check_rx_req(struct cldma_drv_info *drv_info, struct rxq *rxq)
{
	struct rx_req *req = rxq->req_pool + rxq->free_idx;
	u64 curr_addr;
	int i;

	curr_addr = mtk_cldma_get_rx_curr_addr(drv_info, rxq->rxqno);
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
	u32 state;
	int rxqno;

	drv_info = rxq->drv_info;
	rxqno = rxq->rxqno;

	state = mtk_cldma_check_intr_status(drv_info, DIR_RX,
					    rxqno, QUEUE_XFER_DONE);
	if (!state || unlikely(state == LINK_ERROR_VAL))
		return false;

	mtk_cldma_clr_intr_status(drv_info, DIR_RX, rxqno, QUEUE_XFER_DONE);
	cond_resched();
	return true;
}

/* Point the device at the GPD it should fill next and start the queue.
 * free_idx is owned by mtk_cldma_rx_done_work(), so this may only run
 * from that worker, at a point where every consumed GPD is re-armed.
 */
static void mtk_cldma_rxq_restart(struct cldma_drv_info *drv_info, struct rxq *rxq)
{
	mtk_cldma_setup_start_addr(drv_info, DIR_RX, rxq->rxqno,
				   rxq->req_pool[rxq->free_idx].gpd_dma_addr);
	mtk_cldma_start_queue(drv_info, DIR_RX, rxq->rxqno);
}

static void mtk_cldma_rx_done_work(struct work_struct *work)
{
	struct rx_req *req = NULL, *pre_req = NULL;
	struct rxq *rxq = container_of(work, struct rxq, rx_done_work);
	struct cldma_drv_info *drv_info;
	struct mtk_md_dev *mdev;
	struct sk_buff *rx_skb;
	int i, ret, idx, len_err;

	drv_info = rxq->drv_info;
	mdev = drv_info->mdev;

again:
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + rxq->free_idx;
		if (!req->skb) {
			/* An empty slot means an earlier pass could not refill
			 * it and re-queued this work to retry it.
			 */
			if (mtk_cldma_reload_rx_skb(mdev, req))
				goto out_retry;
			goto arm_slot;
		}

		if (req->gpd->rx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO)
			break;

		dma_rmb(); /* read descriptor fields after HWO check */

		len_err = mtk_cldma_rx_skb_adjust(mdev, req);
		rx_skb = req->skb;
		req->skb = NULL;

		ret = mtk_cldma_reload_rx_skb(mdev, req);
		if (ret) {
			/* Alloc failed — recycle old buffer, drop packet. */
			skb_trim(rx_skb, 0);
			req->skb = rx_skb;
			req->data_dma_addr = dma_map_single(mdev->dev,
							    rx_skb->data,
							    req->mtu,
							    DMA_FROM_DEVICE);
			if (dma_mapping_error(mdev->dev, req->data_dma_addr)) {
				/* An unmapped skb left in the slot would be
				 * read back as a completed descriptor.
				 */
				dev_kfree_skb_any(rx_skb);
				req->skb = NULL;
				req->data_dma_addr = 0;
				goto out_retry;
			} else {
				req->gpd->rx_gpd.data_buff_ptr_h =
					cpu_to_le32((u64)req->data_dma_addr >> 32);
				req->gpd->rx_gpd.data_buff_ptr_l =
					cpu_to_le32(req->data_dma_addr);
			}
		} else if (len_err) {
			dev_err_ratelimited(mdev->dev,
					    "Drop oversized packet on cldma%d rxq%u\n",
					    drv_info->hw_id, rxq->rxqno);
			dev_kfree_skb_any(rx_skb);
		} else {
			rxq->rx_done(rx_skb, rxq->arg);
		}

arm_slot:
		wmb(); /* ensure addr set done before HWO setup done  */

		idx = rxq->free_idx == 0 ? rxq->nr_gpds - 1 : rxq->free_idx - 1;
		pre_req = rxq->req_pool + idx;
		pre_req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_HWO;
		rxq->free_idx = (rxq->free_idx + 1) % rxq->nr_gpds;
	}

	ret = mtk_cldma_check_rx_req(drv_info, rxq);
	if (!ret)
		goto again;

	/* -ENXIO means the queue has no start address programmed, which is
	 * exactly what a restart installs, so consume need_restart first.
	 * Only the resume below is skipped in that case.
	 */
	mutex_lock(&drv_info->rearm_lock);
	if (!atomic_read(&rxq->need_exit)) {
		if (atomic_xchg(&rxq->need_restart, 0))
			mtk_cldma_rxq_restart(drv_info, rxq);
		else if (ret != -ENXIO)
			mtk_cldma_resume_queue(drv_info, DIR_RX, rxq->rxqno);
	}
	mutex_unlock(&drv_info->rearm_lock);

	if (ret == -ENXIO)
		goto out;

	if (mtk_cldma_rx_check_again(rxq))
		goto again;
	goto out;

out_retry:
	/* The empty slot keeps the GPD before it unarmed: once the device
	 * has used up the armed ones, no XFER_DONE comes to run this work
	 * again, so retry from here.  The sleep paces a failure that does
	 * not wait, such as a DMA mapping one.
	 */
	usleep_range(1000, 2000);
	if (!atomic_read(&rxq->need_exit))
		queue_work(drv_info->wq, &rxq->rx_done_work);
out:
	mtk_cldma_unmask_intr(drv_info, DIR_RX, rxq->rxqno, QUEUE_XFER_DONE);
	mtk_cldma_clear_ip_busy(drv_info);
}

static struct txq *mtk_cldma_txq_alloc(struct cldma_drv_info *drv_info, struct queue_info *que)
{
	struct mtk_md_dev *mdev;
	struct tx_req *next;
	struct tx_req *req;
	struct txq *txq;
	int i, ret;

	mdev = drv_info->mdev;

	txq = kzalloc_obj(*txq);
	if (!txq)
		return NULL;

	txq->que = que;
	txq->drv_info = drv_info;
	txq->txqno = txq->que->txqno;
	txq->nr_gpds = txq->que->tx_nr_gpds;
	atomic_set(&txq->req_budget, txq->que->tx_nr_gpds);
	spin_lock_init(&txq->ring_lock);

	txq->req_pool = kcalloc(txq->nr_gpds, sizeof(*req), GFP_KERNEL);
	if (!txq->req_pool)
		goto err_free_txq;

	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + i;
		req->mtu = txq->que->tx_mtu;
		req->gpd = dma_pool_zalloc(drv_info->gpd_dma_pool, GFP_KERNEL, &req->gpd_dma_addr);
		if (!req->gpd)
			goto err_free_req;
	}

	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + i;
		next = txq->req_pool + ((i + 1) % txq->nr_gpds);
		req->gpd->tx_gpd.gpd_flags |= CLDMA_GPD_FLAG_IOC;
		req->gpd->tx_gpd.next_gpd_ptr_h = cpu_to_le32((u64)(next->gpd_dma_addr) >> 32);
		req->gpd->tx_gpd.next_gpd_ptr_l = cpu_to_le32(next->gpd_dma_addr);
	}

	INIT_WORK(&txq->tx_done_work, mtk_cldma_tx_done_work);

	ret = mtk_cldma_stop_queue(drv_info, DIR_TX, txq->txqno);
	if (ret) {
		dev_warn(mdev->dev, "Failed to stop TX queue %u before alloc\n", txq->txqno);
		goto err_free_req;
	}
	/* Publish the queue before unmasking its interrupts: an interrupt
	 * that fires in between must find a valid txq, or the sources it
	 * masks are never unmasked again.  Not before the stop: the error
	 * path above frees the queue, so it must never have been visible.
	 * The release pairs with the acquire load in the ISR.
	 */
	smp_store_release(&drv_info->txq[txq->txqno], txq);
	txq->tx_started = false;
	mtk_cldma_setup_start_addr(drv_info, DIR_TX, txq->txqno,
				   txq->req_pool[0].gpd_dma_addr);
	mtk_cldma_unmask_intr(drv_info, DIR_TX, txq->txqno, QUEUE_ERROR);
	mtk_cldma_unmask_intr(drv_info, DIR_TX, txq->txqno, QUEUE_XFER_DONE);

	return txq;

err_free_req:
	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + i;
		if (!req->gpd)
			break;
		dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
	}
	kfree(txq->req_pool);
err_free_txq:
	kfree(txq);
	return NULL;
}

/* mtk_cldma_drv_init() rewrites IP-global configuration (including the interrupt
 * mask) and mtk_cldma_drv_reset() wipes every queue of the instance, so all
 * queues still published in drv_info have to be re-armed, not only the one
 * that triggered the reset.  A queue already unpublished (NULL slot) is being
 * torn down and is deliberately left stopped.
 */
static void mtk_cldma_rearm_queues(struct cldma_drv_info *drv_info)
{
	struct tx_req *req;
	struct txq *txq;
	struct rxq *rxq;
	int i;

	/* The caller holds rearm_lock from the reset to the end of the re-arm:
	 * no queue is kicked or resumed while the instance has no addresses.
	 */
	lockdep_assert_held(&drv_info->rearm_lock);

	mtk_cldma_drv_init(drv_info);

	for (i = 0; i < HW_QUE_NUM; i++) {
		txq = drv_info->txq[i];
		if (txq) {
			spin_lock(&txq->ring_lock);
			/* The device halts on an HWO=0 descriptor and RESUME
			 * never moves the cursor past it, so do not restart
			 * from free_idx - which recovery usually finds behind
			 * the hardware. Leave the queue stopped and let the
			 * next start_xfer() issue a fresh START.
			 */
			req = txq->req_pool + txq->free_idx;
			if (READ_ONCE(txq->tx_started) &&
			    !(req->gpd->tx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO)) {
				WRITE_ONCE(txq->tx_started, false);
				/* Its XFER_DONE may have been lost in the
				 * reset; without this free_idx never advances.
				 */
				queue_work(drv_info->wq, &txq->tx_done_work);
			} else {
				mtk_cldma_setup_start_addr(drv_info, DIR_TX, i,
							   req->gpd_dma_addr);
			}
			mtk_cldma_unmask_intr(drv_info, DIR_TX, i, QUEUE_ERROR);
			mtk_cldma_unmask_intr(drv_info, DIR_TX, i, QUEUE_XFER_DONE);
			if (READ_ONCE(txq->tx_started))
				mtk_cldma_start_queue(drv_info, DIR_TX, i);
			spin_unlock(&txq->ring_lock);
		}

		rxq = drv_info->rxq[i];
		if (rxq) {
			mtk_cldma_unmask_intr(drv_info, DIR_RX, i, QUEUE_ERROR);
			mtk_cldma_unmask_intr(drv_info, DIR_RX, i, QUEUE_XFER_DONE);
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
	struct mtk_md_dev *mdev;
	struct tx_req *req;
	struct txq *txq;
	struct trb *trb;
	int irq_id;
	int i, ret;

	mdev = drv_info->mdev;

	txq = drv_info->txq[txqno];
	/* Unpublish before teardown; pairs with the acquire loads of this
	 * slot. No release is needed, there is no prior store to expose.
	 */
	WRITE_ONCE(drv_info->txq[txqno], NULL);
	/* stop HW tx transaction; -ENODEV means the link is dead, so the
	 * device cannot be walking the ring and the free may proceed.
	 */
	ret = mtk_cldma_stop_queue(drv_info, DIR_TX, txqno);
	if (ret == -ETIMEDOUT) {
		dev_err(mdev->dev, "TX queue %u stop timed out, resetting CLDMA%d\n",
			txqno, drv_info->hw_id);
		/* One rearm_lock section from the reset to the re-arm: no queue
		 * may be resumed or started in between, while it has no address.
		 */
		mutex_lock(&drv_info->rearm_lock);
		mtk_cldma_drv_reset(drv_info);
		ret = mtk_cldma_stop_queue(drv_info, DIR_TX, txqno);
		/* the reset took the whole instance down with this queue */
		mtk_cldma_rearm_queues(drv_info);
		mutex_unlock(&drv_info->rearm_lock);
	}
	txq->tx_started = false;

	irq_id = mtk_pci_get_virq_id(mdev, drv_info->pci_ext_irq_id);
	synchronize_irq(irq_id);
	/* flush on-going work */
	flush_work(&txq->tx_done_work);
	mtk_cldma_mask_intr(drv_info, DIR_TX, txqno, QUEUE_XFER_DONE);
	mtk_cldma_mask_intr(drv_info, DIR_TX, txqno, QUEUE_ERROR);

	if (ret == -ETIMEDOUT) {
		/* Still a live DMA target: leak the ring rather than hand it
		 * back to the allocator.
		 */
		dev_err(mdev->dev, "TX queue %u cannot be stopped, leaking its ring\n",
			txqno);
		return;
	}

	/* Free tx req resource. No ring_lock is taken here: txq was already
	 * unpublished from drv_info->txq[] above, so no new producer can enter,
	 * and synchronize_irq() plus flush_work() have retired the consumer.
	 */
	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + txq->free_idx;
		if (req->skb) {
			dma_unmap_single(mdev->dev, req->data_dma_addr,
					 req->data_len, DMA_TO_DEVICE);
			trb = (struct trb *)req->skb->cb;
			trb->status = -EPIPE;
			trb->trb_complete(req->skb);
		}
		dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
		txq->free_idx = (txq->free_idx + 1) % txq->nr_gpds;
	}

	kfree(txq->req_pool);
	kfree(txq);
}

static void mtk_cldma_rxq_alloc_cancel(struct cldma_drv_info *drv_info, struct rx_req *req)
{
	struct mtk_md_dev *mdev = drv_info->mdev;

	if (req->skb) {
		if (!dma_mapping_error(mdev->dev, req->data_dma_addr))
			dma_unmap_single(mdev->dev, req->data_dma_addr,
					 req->mtu, DMA_FROM_DEVICE);
		req->data_dma_addr = 0;
		dev_kfree_skb_any(req->skb);
	}
	dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
}

static struct rxq *mtk_cldma_rxq_alloc(struct cldma_drv_info *drv_info, struct queue_info *que,
				       struct sk_buff *skb)
{
	struct trb_open_priv *trb_open_priv = (struct trb_open_priv *)skb->data;
	struct trb *trb = (struct trb *)skb->cb;
	struct mtk_md_dev *mdev;
	struct rx_req *next;
	struct rx_req *req;
	struct rxq *rxq;
	int ret;
	int i;

	mdev = drv_info->mdev;

	rxq = kzalloc_obj(*rxq);
	if (!rxq)
		return NULL;

	rxq->que = que;
	rxq->drv_info = drv_info;
	rxq->rxqno = rxq->que->rxqno;
	if (rxq->que->rx_nr_gpds < MIN_GPD_NUM) {
		dev_err(mdev->dev,
			"Failed to alloc cldma%d rxq%u due to gpd number < 2\n",
			drv_info->hw_id, rxq->rxqno);
		goto err_free_rxq;
	}
	rxq->nr_gpds = rxq->que->rx_nr_gpds;
	rxq->arg = trb->priv;
	rxq->rx_done = trb_open_priv->rx_done;
	atomic_set(&rxq->need_exit, 0);
	atomic_set(&rxq->need_restart, 0);

	rxq->req_pool = kcalloc(rxq->nr_gpds, sizeof(*req), GFP_KERNEL);
	if (!rxq->req_pool)
		goto err_free_rxq;

	/* setup rx request */
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + i;
		req->mtu = rxq->que->rx_mtu;
		req->gpd = dma_pool_zalloc(drv_info->gpd_dma_pool, GFP_KERNEL, &req->gpd_dma_addr);
		if (!req->gpd)
			goto err_free_req;
		req->skb = __dev_alloc_skb(req->mtu, GFP_KERNEL);
		if (!req->skb)
			goto err_free_req;
		req->data_dma_addr = dma_map_single(mdev->dev, req->skb->data,
						    req->mtu, DMA_FROM_DEVICE);
		ret = dma_mapping_error(mdev->dev, req->data_dma_addr);
		if (unlikely(ret))
			goto err_free_req;
	}

	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + i;
		next = rxq->req_pool + ((i + 1) % rxq->nr_gpds);
		req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_IOC;
		req->gpd->rx_gpd.data_allow_len = cpu_to_le16(req->mtu);
		req->gpd->rx_gpd.next_gpd_ptr_h = cpu_to_le32((u64)(next->gpd_dma_addr) >> 32);
		req->gpd->rx_gpd.next_gpd_ptr_l = cpu_to_le32(next->gpd_dma_addr);
		req->gpd->rx_gpd.data_buff_ptr_h = cpu_to_le32((u64)(req->data_dma_addr) >> 32);
		req->gpd->rx_gpd.data_buff_ptr_l = cpu_to_le32(req->data_dma_addr);
		if (i != rxq->nr_gpds - 1)
			req->gpd->rx_gpd.gpd_flags |= CLDMA_GPD_FLAG_HWO;
	}

	INIT_WORK(&rxq->rx_done_work, mtk_cldma_rx_done_work);

	ret = mtk_cldma_stop_queue(drv_info, DIR_RX, rxq->rxqno);
	if (ret) {
		dev_warn(mdev->dev, "Failed to stop RX queue %u before alloc\n", rxq->rxqno);
		goto err_free_req;
	}
	/* Pairs with the acquire load in the ISR, as for txq above. */
	smp_store_release(&drv_info->rxq[rxq->rxqno], rxq);
	mtk_cldma_setup_start_addr(drv_info, DIR_RX,
				   rxq->rxqno, rxq->req_pool[0].gpd_dma_addr);
	mtk_cldma_start_queue(drv_info, DIR_RX, rxq->rxqno);
	mtk_cldma_unmask_intr(drv_info, DIR_RX, rxq->rxqno, QUEUE_ERROR);
	mtk_cldma_unmask_intr(drv_info, DIR_RX, rxq->rxqno, QUEUE_XFER_DONE);

	return rxq;

err_free_req:
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + i;
		if (!req->gpd)
			break;
		mtk_cldma_rxq_alloc_cancel(drv_info, req);
	}

	kfree(rxq->req_pool);
err_free_rxq:
	kfree(rxq);
	return NULL;
}

static void mtk_cldma_rxq_free(struct cldma_drv_info *drv_info, u32 rxqno)
{
	struct mtk_md_dev *mdev;
	struct rx_req *req;
	struct rxq *rxq;
	int irq_id;
	int i, ret;

	mdev = drv_info->mdev;

	rxq = drv_info->rxq[rxqno];
	/* Unpublish before teardown; pairs with the acquire loads of this
	 * slot. No release is needed, there is no prior store to expose.
	 */
	WRITE_ONCE(drv_info->rxq[rxqno], NULL);

	/* stop HW rx transaction; -ENODEV means the link is dead, so the
	 * device cannot be walking the ring and the free may proceed.
	 */
	atomic_set(&rxq->need_exit, 1);
	ret = mtk_cldma_stop_queue(drv_info, DIR_RX, rxqno);
	if (ret == -ETIMEDOUT) {
		dev_err(mdev->dev, "RX queue %u stop timed out, resetting CLDMA%d\n",
			rxqno, drv_info->hw_id);
		/* One rearm_lock section from the reset to the re-arm: no queue
		 * may be resumed or started in between, while it has no address.
		 */
		mutex_lock(&drv_info->rearm_lock);
		mtk_cldma_drv_reset(drv_info);
		ret = mtk_cldma_stop_queue(drv_info, DIR_RX, rxqno);
		/* the reset took the whole instance down with this queue */
		mtk_cldma_rearm_queues(drv_info);
		mutex_unlock(&drv_info->rearm_lock);
	}

	irq_id = mtk_pci_get_virq_id(mdev, drv_info->pci_ext_irq_id);
	synchronize_irq(irq_id);
	/* not flush_work(): the worker re-queues itself on a refill failure */
	cancel_work_sync(&rxq->rx_done_work);
	/* a cancelled pass would have cleared it on its way out */
	mtk_cldma_clear_ip_busy(drv_info);
	/* only now: a worker retired by the cancel unmasks XFER_DONE on its
	 * way out
	 */
	mtk_cldma_mask_intr(drv_info, DIR_RX, rxqno, QUEUE_XFER_DONE);
	mtk_cldma_mask_intr(drv_info, DIR_RX, rxqno, QUEUE_ERROR);

	/* The worker can resume or restart the queue between its need_exit
	 * check and the MMIO write that follows it, so cancel_work_sync() does
	 * not prove the engine was left stopped. Stopping again is idempotent.
	 */
	if (ret != -ETIMEDOUT)
		ret = mtk_cldma_stop_queue(drv_info, DIR_RX, rxqno);

	if (ret == -ETIMEDOUT) {
		/* Still a live DMA target: leak the ring rather than hand it
		 * back to the allocator.
		 */
		dev_err(mdev->dev, "RX queue %u cannot be stopped, leaking its ring\n",
			rxqno);
		return;
	}

	/* free rx req resource */
	for (i = 0; i < rxq->nr_gpds; i++) {
		req = rxq->req_pool + rxq->free_idx;
		if (!(req->gpd->rx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO) &&
		    le16_to_cpu(req->gpd->rx_gpd.data_recv_len)) {
			if (!mtk_cldma_rx_skb_adjust(mdev, req)) {
				rxq->rx_done(req->skb, rxq->arg);
				req->skb = NULL;
			}
		}
		if (req->skb) {
			if (req->data_dma_addr)
				dma_unmap_single(mdev->dev, req->data_dma_addr,
						 req->mtu, DMA_FROM_DEVICE);
			dev_kfree_skb_any(req->skb);
			req->skb = NULL;
		}
		dma_pool_free(drv_info->gpd_dma_pool, req->gpd, req->gpd_dma_addr);
		rxq->free_idx = (rxq->free_idx + 1) % rxq->nr_gpds;
	}

	kfree(rxq->req_pool);
	kfree(rxq);
}

/* The device reported a zero TX start address: it lost its queue state. */
static int mtk_cldma_hw_recovery(struct cldma_drv_info *drv_info, struct txq *txq, u32 qno)
{
	u64 val;

	dev_err(drv_info->mdev->dev,
		"CLDMA%d lost its queue state, re-initializing\n",
		drv_info->hw_id);

	mtk_cldma_rearm_queues(drv_info);

	/* A started queue the re-arm left stopped has no address yet, on
	 * purpose: the caller programs one.  Only a dead link, or a 0 on a
	 * queue still marked started, means the re-init failed.
	 */
	val = mtk_cldma_get_tx_start_addr(drv_info, qno);
	if (val == U64_MAX || (!val && READ_ONCE(txq->tx_started)))
		return -EIO;

	return 0;
}

/* After a re-arm the slot at free_idx may hold a descriptor the device
 * completed but tx_done_work has not reaped yet; a START there parks the
 * engine on HWO=0.  Start at the first slot the device still owns.
 */
static u32 mtk_cldma_tx_start_idx(struct txq *txq)
{
	u32 idx = txq->free_idx;
	struct tx_req *req;
	int i;

	for (i = 0; i < txq->nr_gpds; i++) {
		req = txq->req_pool + idx;
		if (!req->skb || (req->gpd->tx_gpd.gpd_flags & CLDMA_GPD_FLAG_HWO))
			return idx;
		idx = (idx + 1) % txq->nr_gpds;
	}

	return txq->free_idx;
}

static int mtk_cldma_start_xfer(struct cldma_drv_info *drv_info, u32 qno)
{
	struct txq *txq;
	int ret = 0;
	u64 val;

	txq = drv_info->txq[qno];

	/* a reset in another queue's teardown must not land between the
	 * address check and the kick
	 */
	mutex_lock(&drv_info->rearm_lock);
	val = mtk_cldma_get_tx_start_addr(drv_info, qno);
	if (unlikely(val == U64_MAX)) {
		ret = -EIO;
		goto out;
	}

	if (unlikely(!val)) {
		ret = mtk_cldma_hw_recovery(drv_info, txq, qno);
		if (ret)
			goto out;
	}

	/* Hold ring_lock across programming and kicking the queue so the
	 * start address given to the device is the one free_idx still
	 * names; tx_done_work advances free_idx under the same lock.
	 */
	spin_lock(&txq->ring_lock);
	if (unlikely(!READ_ONCE(txq->tx_started))) {
		mtk_cldma_setup_start_addr(drv_info, DIR_TX, qno,
					   txq->req_pool[mtk_cldma_tx_start_idx(txq)].gpd_dma_addr);
		mtk_cldma_start_queue(drv_info, DIR_TX, qno);
		WRITE_ONCE(txq->tx_started, true);
	} else {
		mtk_cldma_resume_queue(drv_info, DIR_TX, qno);
	}
	spin_unlock(&txq->ring_lock);
out:
	mutex_unlock(&drv_info->rearm_lock);
	return ret;
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
	if (!trans->dev)
		return;

	kfree(trans->dev);
	trans->dev = NULL;
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

	que = xa_load(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
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
			"Failed to enable cldma%d txq%u rxq%u due to wrong mtu\n",
			drv_info->hw_id, que->txqno, que->rxqno);
		ret = -EINVAL;
		goto out;
	}

	trb_open_priv->tx_mtu = que->tx_mtu;

	if (drv_info->txq[que->txqno] || drv_info->rxq[que->rxqno]) {
		ret = -EBUSY;
		goto out;
	}

	txq = mtk_cldma_txq_alloc(drv_info, que);
	if (!txq) {
		ret = -ENOMEM;
		goto out;
	}

	rxq = mtk_cldma_rxq_alloc(drv_info, que, skb);
	if (!rxq) {
		ret = -ENOMEM;
		mtk_cldma_txq_free(drv_info, txq->txqno);
		goto out;
	}

out:
	/* -EBUSY leaves the channel open to the submitter, so the count this
	 * ENABLE added is released by its eventual DISABLE instead.
	 */
	if (ret && ret != -EBUSY)
		cd->trans->usr_cnt[que->hif_id][que->txqno]--;

	/* Pairs with the acquire load of status on the submitting side: the
	 * payload written to the skb above must be visible with it.
	 */
	smp_store_release(&trb->status, ret);
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
	struct trb_srv *srv;
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

		/* The service may already have been torn down; completing the
		 * TRB is still correct, there is just nobody left to wake.
		 */
		srv = trans->trb_srv[trans->srv_cfg[hif_id][txqno]];
		if (was_starved && srv)
			wake_up(&srv->trb_waitq);
	}
}

static int mtk_cldma_tx(struct cldma_dev *cd, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_info *drv_info;
	struct mtk_md_dev *mdev;
	struct queue_info *que;
	struct txq *txq;
	int ret, err;

	que = xa_load(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
	if (unlikely(!que))
		return -EPIPE;
	drv_info = cd->cldma_drv_info[que->hif_id];
	if (unlikely(!drv_info))
		return -EPIPE;
	txq = drv_info->txq[que->txqno];
	if (unlikely(!txq))
		return -EPIPE;

	mdev = drv_info->mdev;

	ret = mtk_cldma_start_xfer(drv_info, que->txqno);
	if (unlikely(ret)) {
		dev_err(mdev->dev, "Failed to trigger cldma tx\n");
		/* A failed start does not mean the engine is idle - recovery
		 * may already have issued UL_START - and the flush below
		 * unmaps the buffers. If the queue cannot be stopped, leak the
		 * requests rather than unmap memory the device still owns.
		 */
		err = mtk_cldma_stop_queue(drv_info, DIR_TX, que->txqno);
		/* -ENODEV: the link is dead, nothing is walking the ring */
		if (err && err != -ENODEV) {
			dev_err(mdev->dev,
				"TX queue %u stop failed, keeping its requests\n",
				que->txqno);
			return ret;
		}

		spin_lock(&txq->ring_lock);
		WRITE_ONCE(txq->tx_started, false);
		spin_unlock(&txq->ring_lock);
		mtk_cldma_txq_flush(drv_info, txq, ret);
	}

	return ret;
}

static int mtk_cldma_close(struct cldma_dev *cd, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct cldma_drv_info *drv_info;
	struct queue_info *que;

	que = xa_load(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
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
			       struct tx_req *req)
{
	struct mtk_md_dev *mdev = drv_info->mdev;
	int ret;

	/* Only the linear area is mapped; a nonlinear SKB here would be
	 * silently truncated to skb_headlen().
	 */
	if (WARN_ON_ONCE(skb_is_nonlinear(skb)))
		return -EINVAL;

	req->data_dma_addr = dma_map_single(mdev->dev, skb->data,
					    skb_headlen(skb), DMA_TO_DEVICE);
	ret = dma_mapping_error(mdev->dev, req->data_dma_addr);
	if (unlikely(ret)) {
		req->data_dma_addr = 0;
		dev_err_ratelimited(mdev->dev, "Failed to map dma! error:%d\n", ret);
		return -ENOMEM;
	}

	req->gpd->tx_gpd.data_buff_ptr_h = cpu_to_le32((u64)(req->data_dma_addr) >> 32);
	req->gpd->tx_gpd.data_buff_ptr_l = cpu_to_le32(req->data_dma_addr);

	return 0;
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

	if (unlikely(!cd))
		return -EINVAL;

	que = xa_load(&cd->trans->queue_tbl, trb->channel_id & 0xFFFF);
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
	ret = mtk_cldma_txbuf_set(drv_info, skb, req);
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
			"CLDMA%d txq%u rxq%u has not been enabled\n",
			mtk_cldma_hw_id_tbl[que->hif_id], que->txqno, que->rxqno);
		return -EINVAL;
	}

	return 0;
}
