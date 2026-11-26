/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 * Copyright (c) 2015-2016, Mellanox Technologies. All rights reserved.
 */

#ifndef __XSC_QUEUE_H
#define __XSC_QUEUE_H

#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>

#include "common/xsc_core.h"
#include "xsc_eth_wq.h"

struct xsc_channel;

enum {
	XSC_SEND_WQE_DS	= 16,
};

enum {
	XSC_RECV_WQE_DS	= 16,
};

enum {
	XSC_ETH_RQ_STATE_ENABLED,
};

enum {
	XSC_ETH_SQ_STATE_ENABLED,
};

#define XSC_RX_FRAG_SZ_ORDER	0

struct xsc_cq {
	/* data path - accessed per cqe */
	struct xsc_cqwq		wq;

	struct xsc_core_cq	xcq;
	struct xsc_channel	*channel;

	/* control */
	struct xsc_core_device	*xdev;
	struct xsc_wq_ctrl	wq_ctrl;
} ____cacheline_aligned_in_smp;

struct xsc_dma_info {
	struct page	*page;
	dma_addr_t	addr;
};

struct xsc_rq {
	struct xsc_core_qp	cqp;
	struct {
		struct xsc_wq_cyc	wq;
		struct xsc_dma_info	*di;
		u8			wqe_bulk;
	} wqe;

	struct page_pool	*page_pool;
	struct xsc_wq_ctrl	wq_ctrl;
	struct xsc_cq		cq;
	u32			rqn;
	u32			frag_size;

	unsigned long		state;
} ____cacheline_aligned_in_smp;

struct xsc_tx_wqe_info {
	struct sk_buff	*skb;
	dma_addr_t	dma_addr;
};

struct xsc_tx_wqe {
	struct xsc_send_wqe_ctrl_seg ctrl;
	struct xsc_wqe_data_seg data[];
};

struct xsc_sq {
	struct xsc_core_qp		cqp;
	u16				cc;
	u16				pc ____cacheline_aligned_in_smp;

	struct xsc_cq			cq;

	/* read only */
	struct xsc_wq_cyc		wq;
	struct xsc_tx_wqe_info		*wqe_info;
	struct netdev_queue		*txq;
	u32				sqn;
	u16				stop_room;

	unsigned long			state;
	unsigned int			hw_mtu;

	/* control path */
	struct xsc_wq_ctrl		wq_ctrl;
	struct xsc_channel		*channel;
} ____cacheline_aligned_in_smp;

#endif /* __XSC_QUEUE_H */
