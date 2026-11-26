/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ETH_COMMON_H
#define __XSC_ETH_COMMON_H

#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>

#include "xsc_queue.h"

#define SW_DEFAULT_MTU		ETH_DATA_LEN

#define XSC_HASH_IP_PORTS	(BIT(0) | BIT(2) | BIT(3) | BIT(4) | BIT(1))
#define XSC_HASH_IP6_PORTS	(BIT(5) | BIT(6) | BIT(7) | BIT(8) | BIT(1))

enum {
	XSC_HASH_FUNC_TOP		= 1,
};

#define XSC_ETH_HW_MTU_SEND	9800
#define XSC_ETH_HARD_MTU	(ETH_HLEN + VLAN_HLEN * 2 + ETH_FCS_LEN)
#define XSC_SW2HW_MTU(mtu)	((mtu) + XSC_ETH_HARD_MTU)
#define XSC_SW2HW_HLEN		(ETH_HLEN + VLAN_HLEN * 2 + ETH_FCS_LEN)
#define XSC_SW2HW_FRAG_SIZE(mtu)	((mtu) + XSC_SW2HW_HLEN)
#define XSC_ETH_RX_MAX_HEAD_ROOM	256
#define XSC_SW2HW_RX_PKT_LEN(mtu)	\
	((mtu) + ETH_HLEN + XSC_ETH_RX_MAX_HEAD_ROOM)

#define XSC_QPN_SQN_STUB		1025

#define XSC_SKB_FRAG_SZ(len)	(SKB_DATA_ALIGN(len) +	\
				SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

#define XSC_RQCQ_ELE_SZ		32
#define XSC_SQCQ_ELE_SZ		32

#define XSC_LOG_RQCQ_SZ		0xb
#define XSC_LOG_SQCQ_SZ		0xa

#define XSC_RQCQ_ELE_NUM	BIT(XSC_LOG_RQCQ_SZ)
#define XSC_SQCQ_ELE_NUM	BIT(XSC_LOG_SQCQ_SZ)

enum xsc_port_status {
	XSC_PORT_DOWN      = 0,
	XSC_PORT_UP        = 1,
};

enum xsc_queue_type {
	XSC_QUEUE_TYPE_RQCQ,
	XSC_QUEUE_TYPE_SQCQ,
	XSC_QUEUE_TYPE_RQ,
	XSC_QUEUE_TYPE_SQ,
};

struct xsc_queue_attr {
	u32 ele_num;
	u32 ele_size;
	u8  ele_log_size;
	u8  q_log_size;
};

struct xsc_eth_rx_wqe_cyc {
	DECLARE_FLEX_ARRAY(struct xsc_wqe_data_seg, data);
};

struct xsc_cq_param {
	struct xsc_wq_param wq;
	struct xsc_queue_attr cq_attr;
};

struct xsc_rq_param {
	struct xsc_wq_param wq;
	struct xsc_queue_attr rq_attr;
	u32 frag_size;
};

struct xsc_sq_param {
	struct xsc_wq_param wq;
	struct xsc_queue_attr sq_attr;
};

struct xsc_channel_param {
	struct xsc_cq_param rqcq_param;
	struct xsc_cq_param sqcq_param;
	struct xsc_rq_param rq_param;
	struct xsc_sq_param sq_param;
};

struct xsc_eth_qp {
	struct xsc_rq rq;
	struct xsc_sq sq;
};

struct xsc_eth_params {
	u32	mtu;
	u32	sq_size;
	u32	rq_size;
};

struct xsc_channel {
	/* data path */
	struct xsc_eth_qp	qp;

	/* relationship */
	struct xsc_adapter	*adapter;
	struct net_device	*netdev;
	int			cpu;
} ____cacheline_aligned_in_smp;

#endif
