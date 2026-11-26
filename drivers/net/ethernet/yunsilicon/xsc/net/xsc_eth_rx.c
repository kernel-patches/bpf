// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth.h"
#include "xsc_eth_txrx.h"

static void xsc_rq_notify_hw(struct xsc_rq *rq)
{
	struct xsc_core_device *xdev = rq->cq.xdev;

	/* reverse wqe index to ds index */
	xsc_update_rx_db(xdev, rq->rqn,
			 rq->wqe.wq.wqe_ctr << ilog2(xdev->caps.recv_ds_num));
}

static struct sk_buff *xsc_skb_from_cqe(struct xsc_rq *rq,
					struct xsc_dma_info *di,
					u32 cqe_bcnt)
{
	struct sk_buff *skb;
	void *va;
	u32 frag_size;

	va = page_address(di->page);
	frag_size = XSC_SKB_FRAG_SZ(cqe_bcnt);

	dma_sync_single_range_for_cpu(rq->cq.xdev->device, di->addr,
				      0, frag_size, DMA_FROM_DEVICE);
	net_prefetch(va + SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));

	skb = napi_build_skb(va, frag_size);
	if (unlikely(!skb))
		return NULL;

	skb_put(skb, cqe_bcnt);
	skb_mark_for_recycle(skb);

	return skb;
}

static void xsc_dump_error_rqcqe(struct xsc_rq *rq, struct xsc_cqe *cqe)
{
	struct xsc_channel *c = rq->cq.channel;
	u32 data0 = le32_to_cpu(cqe->data0);

	net_err_ratelimited("Error cqe on dev=%s, cqn=%d, ci=%d, rqn=%d, qpn=%lu, error_code=0x%lx\n",
			    c->netdev->name, rq->cq.xcq.cqn,
			    xsc_cqwq_get_ci(&rq->cq.wq), rq->rqn,
			    FIELD_GET(XSC_CQE_DATA0_QP_ID_MASK, data0),
			    FIELD_GET(XSC_CQE_DATA0_ERR_CODE_MASK, data0));
}

void xsc_eth_handle_rx_cqe(struct xsc_rq *rq, struct xsc_cqe *cqe)
{
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	struct xsc_dma_info *di;
	struct sk_buff *skb;
	u32 cqe_bcnt;
	u16 ci;

	ci = xsc_wq_cyc_ctr2ix(wq, rq->cq.wq.cc);
	di = &rq->wqe.di[ci];

	if (unlikely(le32_to_cpu(cqe->data0) & XSC_CQE_DATA0_IS_ERR)) {
		xsc_dump_error_rqcqe(rq, cqe);
		page_pool_recycle_direct(rq->page_pool, di->page);
		di->page = NULL;
		xsc_wq_cyc_pop(wq);
		return;
	}

	cqe_bcnt = le32_to_cpu(cqe->msg_len);
	skb = (cqe_bcnt >= ETH_HLEN && cqe_bcnt <= rq->frag_size) ?
	      xsc_skb_from_cqe(rq, di, cqe_bcnt) : NULL;

	if (skb) {
		skb_record_rx_queue(skb, 0);
		skb->protocol = eth_type_trans(skb, rq->cq.channel->netdev);

		napi_gro_receive(rq->cq.napi, skb);
	} else {
		/* when the skb took the page, it recycles it via pp_recycle */
		page_pool_recycle_direct(rq->page_pool, di->page);
	}
	di->page = NULL;

	xsc_wq_cyc_pop(wq);
}

int xsc_poll_rx_cq(struct xsc_cq *cq, int budget)
{
	struct xsc_rq *rq = container_of(cq, struct xsc_rq, cq);
	struct xsc_cqe *cqe;
	int work_done = 0;

	if (!test_bit(XSC_ETH_RQ_STATE_ENABLED, &rq->state))
		return 0;

	while (work_done < budget) {
		cqe = xsc_cqwq_get_cqe(&cq->wq);
		if (!cqe)
			break;
		/* ensure cqe content is read after cqe ownership bit */
		dma_rmb();

		xsc_eth_handle_rx_cqe(rq, cqe);
		++work_done;

		xsc_cqwq_pop(&cq->wq);
	}

	if (work_done)
		xsc_cq_notify_hw(cq);

	return work_done;
}

void xsc_eth_dealloc_rx_wqe(struct xsc_rq *rq, u16 ix)
{
	struct xsc_dma_info *di = &rq->wqe.di[ix];

	if (!di->page)
		return;

	page_pool_recycle_direct(rq->page_pool, di->page);
	di->page = NULL;
}

static int xsc_alloc_rx_wqes(struct xsc_rq *rq, u16 head, int bulk)
{
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	struct xsc_dma_info *di;
	struct xsc_eth_rx_wqe_cyc *wqe;
	int i;

	for (i = 0; i < bulk; i++) {
		u16 ix = xsc_wq_cyc_ctr2ix(wq, head + i);

		di = &rq->wqe.di[ix];
		di->page = page_pool_dev_alloc_pages(rq->page_pool);
		if (unlikely(!di->page)) {
			while (--i >= 0)
				xsc_eth_dealloc_rx_wqe(rq,
						       xsc_wq_cyc_ctr2ix(wq, head + i));
			return -ENOMEM;
		}
		di->addr = page_pool_get_dma_addr(di->page);

		wqe = xsc_wq_cyc_get_wqe(wq, ix);
		wqe->data[0].va = cpu_to_le64(di->addr);
	}

	return 0;
}

bool xsc_eth_post_rx_wqes(struct xsc_rq *rq)
{
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	int alloc;
	u16 head;

	if (xsc_wq_cyc_missing(wq) < rq->wqe.wqe_bulk)
		return false;

	do {
		head = xsc_wq_cyc_get_head(wq);
		alloc = min_t(int, rq->wqe.wqe_bulk, xsc_wq_cyc_missing(wq));

		if (xsc_alloc_rx_wqes(rq, head, alloc))
			return true;

		xsc_wq_cyc_push_n(wq, alloc);
	} while (xsc_wq_cyc_missing(wq) >= rq->wqe.wqe_bulk);

	dma_wmb();

	/* ensure wqes are visible to device before updating doorbell record */
	xsc_rq_notify_hw(rq);

	return false;
}

int xsc_eth_napi_poll(struct napi_struct *napi, int budget)
{
	struct xsc_channel *c = container_of(napi, struct xsc_channel, napi);
	struct xsc_rq *rq = &c->qp.rq;
	bool busy;
	int work_done;

	busy = xsc_poll_tx_cq(&c->qp.sq.cq, xsc_cqwq_get_size(&c->qp.sq.cq.wq));

	work_done = xsc_poll_rx_cq(&rq->cq, budget);
	busy |= work_done == budget;

	if (xsc_eth_post_rx_wqes(rq))
		busy = true;

	if (busy)
		return budget;

	if (unlikely(!napi_complete_done(napi, work_done)))
		return work_done;

	xsc_cq_notify_hw_rearm(&c->qp.sq.cq);
	xsc_cq_notify_hw_rearm(&rq->cq);

	return work_done;
}
