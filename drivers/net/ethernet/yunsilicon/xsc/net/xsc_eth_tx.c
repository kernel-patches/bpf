// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth.h"
#include "xsc_eth_txrx.h"

#define XSC_OPCODE_RAW			7

netdev_tx_t xsc_eth_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_send_wqe_ctrl_seg *cseg;
	struct xsc_tx_wqe_info *wi;
	struct xsc_sq *sq = &adapter->channel.qp.sq;
	struct xsc_tx_wqe *wqe;
	u32 ds_num_log = ilog2(xdev->caps.send_ds_num);
	dma_addr_t dma_addr;
	u16 pi;

	if (!adapter->opened)
		return NETDEV_TX_BUSY;

	if (unlikely(skb_is_nonlinear(skb) || skb->len == 0 ||
		     skb->len > sq->hw_mtu))
		goto err_drop;

	pi = xsc_wq_cyc_ctr2ix(&sq->wq, sq->pc);
	wqe = xsc_wq_cyc_get_wqe(&sq->wq, pi);
	memset(wqe, 0, xdev->caps.send_ds_num * XSC_SEND_WQE_DS);

	dma_addr = dma_map_single(sq->channel->adapter->dev, skb->data,
				  skb->len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(sq->channel->adapter->dev, dma_addr)))
		goto err_drop;

	wi = &sq->wqe_info[pi];
	wi->skb = skb;
	wi->dma_addr = dma_addr;

	cseg = &wqe->ctrl;
	cseg->data0 = cpu_to_le32(FIELD_PREP(XSC_WQE_CTRL_SEG_DATA0_MSG_OPCODE_MASK,
					     XSC_OPCODE_RAW) |
				  FIELD_PREP(XSC_WQE_CTRL_SEG_DATA0_DS_DATA_NUM_MASK,
					     1) |
				  FIELD_PREP(XSC_WQE_CTRL_SEG_DATA0_WQE_ID_MASK,
					     sq->pc << ds_num_log));
	cseg->msg_len = cpu_to_le32(skb->len);
	cseg->data3 = cpu_to_le32(XSC_WQE_CTRL_SEG_DATA3_CE);
	wqe->data[0].data0 =
		cpu_to_le32(FIELD_PREP(XSC_WQE_DATA_SEG_DATA0_SEG_LEN_MASK,
				       skb->len));
	wqe->data[0].va = cpu_to_le64(dma_addr);

	sq->pc++;
	if (unlikely(!xsc_wqc_has_room_for(&sq->wq, sq->cc, sq->pc,
					   sq->stop_room)))
		netif_tx_stop_queue(sq->txq);

	if (!netdev_xmit_more() || netif_xmit_stopped(sq->txq))
		xsc_update_tx_db(xdev, sq->sqn, sq->pc << ds_num_log);

	return NETDEV_TX_OK;

err_drop:
	dev_kfree_skb_any(skb);
	if (!netdev_xmit_more() || netif_xmit_stopped(sq->txq))
		xsc_update_tx_db(xdev, sq->sqn, sq->pc << ds_num_log);
	return NETDEV_TX_OK;
}

void xsc_free_tx_wqe(struct device *dev, struct xsc_sq *sq)
{
	for (; sq->cc != sq->pc; sq->cc++) {
		struct xsc_tx_wqe_info *wi =
			&sq->wqe_info[xsc_wq_cyc_ctr2ix(&sq->wq, sq->cc)];

		if (!wi->skb)
			continue;

		dma_unmap_single(dev, wi->dma_addr, wi->skb->len,
				 DMA_TO_DEVICE);
		dev_kfree_skb_any(wi->skb);
	}
}
