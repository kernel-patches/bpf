// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd. All
 * rights reserved.
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
 */

#include "xsc_eth_wq.h"
#include "xsc_eth.h"

u32 xsc_wq_cyc_get_size(struct xsc_wq_cyc *wq)
{
	return (u32)wq->fbc.sz_m1 + 1;
}

static u32 wq_get_byte_sz(u8 log_sz, u8 log_stride)
{
	return ((u32)1 << log_sz) << log_stride;
}

int xsc_eth_cqwq_create(struct xsc_core_device *xdev,
			struct xsc_wq_param *param,
			u8 q_log_size,
			u8 ele_log_size,
			struct xsc_cqwq *wq,
			struct xsc_wq_ctrl *wq_ctrl)
{
	u8 log_wq_stride = ele_log_size;
	u8 log_wq_sz     = q_log_size;
	int err;

	err = xsc_core_frag_buf_alloc_node(xdev,
					   wq_get_byte_sz(log_wq_sz,
							  log_wq_stride),
					   &wq_ctrl->buf,
					   param->buf_numa_node);
	if (err) {
		netdev_err(xsc_dev_to_netdev(xdev),
			   "xsc_core_frag_buf_alloc_node failed, %d\n", err);
		return err;
	}

	xsc_init_fbc(wq_ctrl->buf.frags, log_wq_stride, log_wq_sz, &wq->fbc);
	wq_ctrl->xdev = xdev;
	return 0;
}

int xsc_eth_wq_cyc_create(struct xsc_core_device *xdev,
			  struct xsc_wq_param *param,
			  u8 q_log_size,
			  u8 ele_log_size,
			  struct xsc_wq_cyc *wq,
			  struct xsc_wq_ctrl *wq_ctrl)
{
	struct xsc_frag_buf_ctrl *fbc = &wq->fbc;
	u8 log_wq_stride = ele_log_size;
	u8 log_wq_sz = q_log_size;
	int err;

	err = xsc_core_frag_buf_alloc_node(xdev,
					   wq_get_byte_sz(log_wq_sz,
							  log_wq_stride),
					   &wq_ctrl->buf,
					   param->buf_numa_node);
	if (err) {
		netdev_err(xsc_dev_to_netdev(xdev),
			   "xsc_core_frag_buf_alloc_node failed, %d\n", err);
		return err;
	}

	xsc_init_fbc(wq_ctrl->buf.frags, log_wq_stride, log_wq_sz, fbc);
	wq->sz = xsc_wq_cyc_get_size(wq);
	wq_ctrl->xdev = xdev;
	return 0;
}

void xsc_eth_wq_destroy(struct xsc_wq_ctrl *wq_ctrl)
{
	xsc_core_frag_buf_free(wq_ctrl->xdev, &wq_ctrl->buf);
}
