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

struct xsc_cqe *xsc_cqwq_get_cqe(struct xsc_cqwq *wq);

static inline bool xsc_wqc_has_room_for(struct xsc_wq_cyc *wq,
					u16 cc, u16 pc, u16 n)
{
	return (xsc_wq_cyc_ctr2ix(wq, cc - pc) >= n) || (cc == pc);
}

#endif /* __XSC_ETH_TXRX_H */
