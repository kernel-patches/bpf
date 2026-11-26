// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth.h"
#include "xsc_eth_txrx.h"

struct xsc_cqe *xsc_cqwq_get_cqe(struct xsc_cqwq *wq)
{
	struct xsc_cqe *cqe = xsc_frag_buf_get_wqe(&wq->fbc,
						   xsc_cqwq_get_ci(wq));

	if (!!(le32_to_cpu(cqe->data1) & XSC_CQE_DATA1_OWNER) !=
	    (xsc_cqwq_get_wrap_cnt(wq) & 1))
		return NULL;

	return cqe;
}

int xsc_poll_tx_cq(struct xsc_cq *cq, int budget)
{
	struct xsc_cqe *cqe;
	struct device *dev;
	struct xsc_sq *sq;
	u16 sqcc;
	int i = 0;

	sq = container_of(cq, struct xsc_sq, cq);
	if (!test_bit(XSC_ETH_SQ_STATE_ENABLED, &sq->state))
		return 0;

	dev = sq->channel->adapter->dev;
	sqcc = sq->cc;

	while (i < budget) {
		struct xsc_tx_wqe_info *wi;
		struct sk_buff *skb;

		cqe = xsc_cqwq_get_cqe(&cq->wq);
		if (!cqe)
			break;
		/* ensure cqe content is read after cqe ownership bit */
		dma_rmb();

		xsc_cqwq_pop(&cq->wq);
		wi = &sq->wqe_info[xsc_wq_cyc_ctr2ix(&sq->wq, sqcc)];

		skb = wi->skb;
		wi->skb = NULL;
		if (skb) {
			dma_unmap_single(dev, wi->dma_addr, skb->len,
					 DMA_TO_DEVICE);
			dev_kfree_skb_any(skb);
		}

		sqcc++;
		i++;
	}

	xsc_update_cq_ci(cq->xdev, cq->xcq.cqn, cq->wq.cc);

	sq->cc = sqcc;

	if (netif_tx_queue_stopped(sq->txq) &&
	    xsc_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, sq->stop_room))
		netif_tx_wake_queue(sq->txq);

	return i == budget;
}
