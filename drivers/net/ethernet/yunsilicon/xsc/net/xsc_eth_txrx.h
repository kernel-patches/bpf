/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ETH_TXRX_H
#define __XSC_ETH_TXRX_H

#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include "xsc_eth.h"

int xsc_poll_tx_cq(struct xsc_cq *cq, int budget);
void xsc_free_tx_wqe(struct device *dev, struct xsc_sq *sq);
netdev_tx_t xsc_eth_xmit(struct sk_buff *skb, struct net_device *netdev);

int xsc_poll_rx_cq(struct xsc_cq *cq, int budget);
int xsc_eth_napi_poll(struct napi_struct *napi, int budget);
void xsc_eth_handle_rx_cqe(struct xsc_rq *rq, struct xsc_cqe *cqe);
bool xsc_eth_post_rx_wqes(struct xsc_rq *rq);
void xsc_eth_dealloc_rx_wqe(struct xsc_rq *rq, u16 ix);

struct xsc_cqe *xsc_cqwq_get_cqe(struct xsc_cqwq *wq);

static inline bool xsc_wqc_has_room_for(struct xsc_wq_cyc *wq,
					u16 cc, u16 pc, u16 n)
{
	return (xsc_wq_cyc_ctr2ix(wq, cc - pc) >= n) || (cc == pc);
}

void xsc_cq_notify_hw(struct xsc_cq *cq);
void xsc_cq_notify_hw_rearm(struct xsc_cq *cq);

#endif /* __XSC_ETH_TXRX_H */
