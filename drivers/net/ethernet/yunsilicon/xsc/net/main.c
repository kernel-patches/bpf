// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/auxiliary_bus.h>
#include <linux/irq.h>

#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "xsc_eth_common.h"
#include "xsc_eth.h"
#include "xsc_eth_txrx.h"

static void xsc_eth_build_nic_params(struct xsc_adapter *adapter)
{
	struct xsc_eth_params *params = &adapter->nic_param;

	params->mtu = SW_DEFAULT_MTU;
}

static void xsc_eth_netdev_init(struct xsc_adapter *adapter)
{
	netif_carrier_off(adapter->netdev);
}

static void xsc_eth_build_queue_param(struct xsc_adapter *adapter,
				      struct xsc_queue_attr *attr, u8 type)
{
	struct xsc_core_device *xdev = adapter->xdev;

	if (adapter->nic_param.sq_size == 0)
		adapter->nic_param.sq_size = min_t(u32,
						   BIT(xdev->caps.log_max_qp_depth),
						   XSC_SQCQ_ELE_NUM);
	if (adapter->nic_param.rq_size == 0)
		adapter->nic_param.rq_size = BIT(xdev->caps.log_max_qp_depth);

	if (type == XSC_QUEUE_TYPE_RQCQ) {
		attr->ele_num = min_t(int, XSC_RQCQ_ELE_NUM,
				      xdev->caps.max_cqes);
		attr->ele_size = XSC_RQCQ_ELE_SZ;
		attr->ele_log_size = order_base_2(XSC_RQCQ_ELE_SZ);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_SQCQ) {
		attr->ele_num = min_t(int, XSC_SQCQ_ELE_NUM,
				      xdev->caps.max_cqes);
		attr->ele_size = XSC_SQCQ_ELE_SZ;
		attr->ele_log_size = order_base_2(XSC_SQCQ_ELE_SZ);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_RQ) {
		attr->ele_num = adapter->nic_param.rq_size;
		attr->ele_size = xdev->caps.recv_ds_num * XSC_RECV_WQE_DS;
		attr->ele_log_size = order_base_2(attr->ele_size);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_SQ) {
		attr->ele_num = adapter->nic_param.sq_size;
		attr->ele_size = xdev->caps.send_ds_num * XSC_SEND_WQE_DS;
		attr->ele_log_size = order_base_2(attr->ele_size);
		attr->q_log_size = order_base_2(attr->ele_num);
	}
}

static u32 xsc_rx_get_linear_frag_sz(u32 mtu)
{
	return XSC_SKB_FRAG_SZ(XSC_SW2HW_FRAG_SIZE(mtu));
}

static void xsc_eth_build_channel_param(struct xsc_adapter *adapter,
					struct xsc_channel_param *chl_param)
{
	xsc_eth_build_queue_param(adapter, &chl_param->rqcq_param.cq_attr,
				  XSC_QUEUE_TYPE_RQCQ);
	chl_param->rqcq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_eth_build_queue_param(adapter, &chl_param->sqcq_param.cq_attr,
				  XSC_QUEUE_TYPE_SQCQ);
	chl_param->sqcq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_eth_build_queue_param(adapter, &chl_param->sq_param.sq_attr,
				  XSC_QUEUE_TYPE_SQ);
	chl_param->sq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_eth_build_queue_param(adapter, &chl_param->rq_param.rq_attr,
				  XSC_QUEUE_TYPE_RQ);
	chl_param->rq_param.wq.buf_numa_node = dev_to_node(adapter->dev);
	chl_param->rq_param.frag_size = XSC_SW2HW_FRAG_SIZE(adapter->nic_param.mtu);
}

static void xsc_eth_cq_error_event(struct xsc_core_cq *xcq,
				   enum xsc_event event)
{
	struct xsc_cq *xsc_cq = container_of(xcq, struct xsc_cq, xcq);
	struct xsc_core_device *xdev = xsc_cq->xdev;

	if (event != XSC_EVENT_TYPE_CQ_ERROR) {
		netdev_err(xsc_dev_to_netdev(xdev),
			   "Unexpected event type %d on CQ %06x\n",
			   event, xcq->cqn);
		return;
	}

	netdev_err(xsc_dev_to_netdev(xdev),
		   "Eth catch CQ ERROR: %x, cqn: %d\n", event, xcq->cqn);
}

static void xsc_eth_comp(struct xsc_core_cq *xcq)
{
	struct xsc_cq *cq = container_of(xcq, struct xsc_cq, xcq);

	napi_schedule(cq->napi);
}

static int xsc_eth_alloc_cq(struct xsc_channel *c, struct xsc_cq *pcq,
			    struct xsc_cq_param *pcq_param)
{
	u8 ele_log_size = pcq_param->cq_attr.ele_log_size;
	struct xsc_core_device *xdev = c->adapter->xdev;
	u8 q_log_size = pcq_param->cq_attr.q_log_size;
	struct xsc_core_cq *core_cq = &pcq->xcq;
	int ret;
	u32 i;

	pcq_param->wq.db_numa_node = cpu_to_node(c->cpu);
	pcq_param->wq.buf_numa_node = cpu_to_node(c->cpu);

	ret = xsc_eth_cqwq_create(xdev, &pcq_param->wq,
				  q_log_size, ele_log_size, &pcq->wq,
				  &pcq->wq_ctrl);
	if (ret)
		return ret;

	core_cq->comp = xsc_eth_comp;
	core_cq->event = xsc_eth_cq_error_event;
	core_cq->vector = 0;

	for (i = 0; i < xsc_cqwq_get_size(&pcq->wq); i++) {
		struct xsc_cqe *cqe = xsc_cqwq_get_wqe(&pcq->wq, i);

		cqe->data1 |= cpu_to_le32(XSC_CQE_DATA1_OWNER);
	}
	pcq->xdev = xdev;
	return 0;
}

static int xsc_eth_set_cq(struct xsc_channel *c,
			  struct xsc_cq *pcq,
			  struct xsc_cq_param *pcq_param)
{
	struct xsc_core_device *xdev = c->adapter->xdev;
	struct xsc_create_cq_mbox_in *in;
	unsigned int hw_npages;
	unsigned int irqn;
	int inlen;
	u32 eqn;
	int ret;

	hw_npages = DIV_ROUND_UP(pcq->wq_ctrl.buf.size, XSC_PAGE_SIZE_4K);
	/*mbox size + pas size*/
	inlen = sizeof(struct xsc_create_cq_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	ret = xsc_core_vector2eqn(xdev, pcq->xcq.vector, &eqn, &irqn);
	if (ret)
		goto err_free;

	in->ctx.eqn = cpu_to_be16(eqn);
	in->ctx.log_cq_sz = pcq_param->cq_attr.q_log_size;
	in->ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx.glb_func_id = cpu_to_be16(xdev->glb_func_id);

	xsc_core_fill_page_frag_array(&pcq->wq_ctrl.buf,
				      &in->pas[0],
				      hw_npages);

	ret = xsc_core_eth_create_cq(xdev, &pcq->xcq, in, inlen);
	if (ret)
		goto err_free;
	pcq->xcq.irqn = irqn;
	kvfree(in);
	return 0;

err_free:
	kvfree(in);
	return ret;
}

static void xsc_eth_free_cq(struct xsc_cq *cq)
{
	xsc_eth_wq_destroy(&cq->wq_ctrl);
}

static int xsc_eth_open_cq(struct xsc_channel *c,
			   struct xsc_cq *pcq,
			   struct xsc_cq_param *pcq_param)
{
	int ret;

	ret = xsc_eth_alloc_cq(c, pcq, pcq_param);
	if (ret)
		return ret;

	ret = xsc_eth_set_cq(c, pcq, pcq_param);
	if (ret)
		goto err_free_cq;

	xsc_arm_cq(pcq->xdev, pcq->xcq.cqn, pcq->wq.cc, 0);

	pcq->napi = &c->napi;
	pcq->channel = c;

	return 0;

err_free_cq:
	xsc_eth_free_cq(pcq);
	return ret;
}

static void xsc_eth_close_cq(struct xsc_channel *c, struct xsc_cq *pcq)
{
	struct xsc_core_device *xdev = c->adapter->xdev;

	/* If DESTROY_CQ failed the firmware may still own this CQ and keep
	 * writing CQEs into its buffer; leak the buffer rather than hand it
	 * back to the allocator while the device can still DMA into it.
	 */
	if (xsc_core_eth_destroy_cq(xdev, &pcq->xcq)) {
		netdev_err(xsc_dev_to_netdev(xdev), "failed to close cq%d\n",
			   pcq->xcq.cqn);
		return;
	}

	xsc_eth_free_cq(pcq);
}

static void xsc_free_qp_sq_db(struct xsc_sq *sq)
{
	kvfree(sq->wqe_info);
	sq->wqe_info = NULL;
}

static void xsc_free_qp_sq(struct xsc_sq *sq)
{
	xsc_free_qp_sq_db(sq);
	xsc_eth_wq_destroy(&sq->wq_ctrl);
}

static int xsc_eth_alloc_qp_sq_db(struct xsc_sq *sq, int numa)
{
	sq->wqe_info = kvzalloc_node(array_size(xsc_wq_cyc_get_size(&sq->wq),
						sizeof(*sq->wqe_info)),
				     GFP_KERNEL, numa);
	if (!sq->wqe_info)
		return -ENOMEM;

	return 0;
}

static void xsc_eth_qp_event(struct xsc_core_qp *qp, int type)
{
	struct xsc_core_device *xdev;
	struct xsc_rq *rq;
	struct xsc_sq *sq;

	if (qp->eth_queue_type == XSC_RES_RQ) {
		rq = container_of(qp, struct xsc_rq, cqp);
		xdev = rq->cq.xdev;
	} else if (qp->eth_queue_type == XSC_RES_SQ) {
		sq = container_of(qp, struct xsc_sq, cqp);
		xdev = sq->cq.xdev;
	} else {
		pr_err("%s:Unknown eth qp type %d\n", __func__, type);
		return;
	}

	switch (type) {
	case XSC_EVENT_TYPE_WQ_CATAS_ERROR:
	case XSC_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
	case XSC_EVENT_TYPE_WQ_ACCESS_ERROR:
		netdev_err(xsc_dev_to_netdev(xdev),
			   "%s:Async event %x on QP %d\n",
			   __func__, type, qp->qpn);
		break;
	default:
		netdev_err(xsc_dev_to_netdev(xdev),
			   "%s: Unexpected event type %d on QP %d\n",
			   __func__, type, qp->qpn);
		return;
	}
}

static int xsc_eth_open_qp_sq(struct xsc_channel *c,
			      struct xsc_sq *psq,
			      struct xsc_sq_param *psq_param)
{
	u8 ele_log_size = psq_param->sq_attr.ele_log_size;
	u8 q_log_size = psq_param->sq_attr.q_log_size;
	struct xsc_modify_raw_qp_mbox_in *modify_in;
	struct xsc_create_qp_mbox_in *in;
	struct xsc_core_device *xdev;
	struct xsc_adapter *adapter;
	unsigned int hw_npages;
	int inlen;
	int ret;

	adapter = c->adapter;
	xdev  = adapter->xdev;
	psq_param->wq.db_numa_node = cpu_to_node(c->cpu);

	ret = xsc_eth_wq_cyc_create(xdev, &psq_param->wq,
				    q_log_size, ele_log_size, &psq->wq,
				    &psq->wq_ctrl);
	if (ret)
		return ret;

	hw_npages = DIV_ROUND_UP(psq->wq_ctrl.buf.size, XSC_PAGE_SIZE_4K);
	inlen = sizeof(struct xsc_create_qp_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto err_sq_wq_destroy;
	}
	in->req.input_qpn = cpu_to_be16(XSC_QPN_SQN_STUB);
	in->req.qp_type = XSC_QUEUE_TYPE_RAW_TSO;
	in->req.log_sq_sz = ilog2(xdev->caps.send_ds_num) + q_log_size;
	in->req.pa_num = cpu_to_be16(hw_npages);
	in->req.cqn_send = cpu_to_be16(psq->cq.xcq.cqn);
	in->req.cqn_recv = in->req.cqn_send;
	in->req.glb_funcid = cpu_to_be16(xdev->glb_func_id);

	xsc_core_fill_page_frag_array(&psq->wq_ctrl.buf,
				      &in->req.pas[0], hw_npages);

	ret = xsc_core_eth_create_qp(xdev, in, inlen, &psq->sqn);
	if (ret)
		goto err_sq_in_destroy;

	psq->cqp.qpn = psq->sqn;
	psq->cqp.event = xsc_eth_qp_event;
	psq->cqp.eth_queue_type = XSC_RES_SQ;

	ret = xsc_core_create_resource_common(xdev, &psq->cqp);
	if (ret) {
		netdev_err(adapter->netdev, "%s:error qp:%d errno:%d\n",
			   __func__, psq->sqn, ret);
		goto err_sq_destroy;
	}

	psq->channel = c;

	psq->hw_mtu = XSC_ETH_HW_MTU_SEND;
	psq->stop_room = 1;

	ret = xsc_eth_alloc_qp_sq_db(psq, psq_param->wq.db_numa_node);
	if (ret)
		goto err_sq_common_destroy;

	inlen = sizeof(struct xsc_modify_raw_qp_mbox_in);
	modify_in = kvzalloc(inlen, GFP_KERNEL);
	if (!modify_in) {
		ret = -ENOMEM;
		goto err_sq_common_destroy;
	}

	modify_in->req.qp_out_port = xdev->pf_id;
	modify_in->pcie_no = xdev->pcie_no;
	modify_in->req.qpn = cpu_to_be16((u16)(psq->sqn));
	modify_in->req.func_id = cpu_to_be16(xdev->glb_func_id);
	modify_in->req.dma_direct = XSC_DMA_DIR_TO_MAC;
	modify_in->req.prio = 0;
	ret = xsc_core_eth_modify_raw_qp(xdev, modify_in);
	if (ret)
		goto err_sq_modify_in_destroy;

	kvfree(modify_in);
	kvfree(in);

	return 0;

err_sq_modify_in_destroy:
	kvfree(modify_in);

err_sq_common_destroy:
	xsc_free_qp_sq_db(psq);

	xsc_core_destroy_resource_common(xdev, &psq->cqp);

err_sq_destroy:
	xsc_core_eth_destroy_qp(xdev, psq->cqp.qpn);

err_sq_in_destroy:
	kvfree(in);

err_sq_wq_destroy:
	xsc_eth_wq_destroy(&psq->wq_ctrl);
	return ret;
}

static void xsc_eth_close_qp_sq(struct xsc_channel *c, struct xsc_sq *psq)
{
	struct xsc_core_device *xdev = c->adapter->xdev;

	xsc_core_destroy_resource_common(xdev, &psq->cqp);

	/* If DESTROY_QP failed the QP is still live in the firmware with its
	 * WQ pages programmed; leak the WQ buffer (and in-flight skbs) rather
	 * than free pages the device can still DMA into.
	 */
	if (xsc_core_eth_destroy_qp(xdev, psq->cqp.qpn)) {
		netdev_err(c->adapter->netdev, "failed to close sq%d\n",
			   psq->cqp.qpn);
		return;
	}

	xsc_free_tx_wqe(c->adapter->dev, psq);
	xsc_free_qp_sq(psq);
}

static int xsc_eth_open_channel(struct xsc_adapter *adapter,
				struct xsc_channel *c,
				struct xsc_channel_param *chl_param)
{
	struct xsc_core_device *xdev = adapter->xdev;
	const struct cpumask *aff;
	unsigned int irqn;
	u32 eqn;
	int ret;

	c->adapter = adapter;
	c->netdev = adapter->netdev;
	c->cpu = 0;

	ret = xsc_core_vector2eqn(xdev, 0, &eqn, &irqn);
	if (ret)
		goto err_out;
	aff = irq_get_affinity_mask(irqn);
	if (aff)
		c->cpu = cpumask_first(aff);

	ret = xsc_eth_open_cq(c, &c->qp.rq.cq, &chl_param->rqcq_param);
	if (ret)
		goto err_out;

	ret = xsc_eth_open_cq(c, &c->qp.sq.cq, &chl_param->sqcq_param);
	if (ret)
		goto err_close_rq_cq;

	ret = xsc_eth_open_qp_sq(c, &c->qp.sq, &chl_param->sq_param);
	if (ret)
		goto err_close_sq_cq;

	netif_napi_add(adapter->netdev, &c->napi, xsc_eth_napi_poll);

	netdev_dbg(adapter->netdev, "open channel ok\n");
	return 0;

err_close_sq_cq:
	xsc_eth_close_cq(c, &c->qp.sq.cq);
err_close_rq_cq:
	xsc_eth_close_cq(c, &c->qp.rq.cq);
err_out:
	netdev_err(adapter->netdev, "failed to open channel, err=%d\n", ret);
	return ret;
}

static int xsc_eth_modify_qps_channel(struct xsc_adapter *adapter,
				      struct xsc_channel *c)
{
	int ret;

	xsc_eth_post_rx_wqes(&c->qp.rq);

	ret = xsc_core_eth_modify_qp_status(adapter->xdev, c->qp.rq.rqn,
					    XSC_CMD_OP_RTR2RTS_QP);
	if (ret)
		return ret;

	return xsc_core_eth_modify_qp_status(adapter->xdev, c->qp.sq.sqn,
					     XSC_CMD_OP_RTR2RTS_QP);
}

static void xsc_eth_free_qp_rq(struct xsc_rq *rq)
{
	kvfree(rq->wqe.di);

	if (rq->page_pool)
		page_pool_destroy(rq->page_pool);

	xsc_eth_wq_destroy(&rq->wq_ctrl);
}

static int xsc_eth_alloc_rq(struct xsc_channel *c,
			    struct xsc_rq *prq,
			    struct xsc_rq_param *prq_param)
{
	u8 ele_log_size = prq_param->rq_attr.ele_log_size;
	struct page_pool_params pagepool_params = {0};
	u8 q_log_size = prq_param->rq_attr.q_log_size;
	u32 wq_sz;
	int ret = 0;
	int i;

	prq_param->wq.db_numa_node = cpu_to_node(c->cpu);

	ret = xsc_eth_wq_cyc_create(c->adapter->xdev, &prq_param->wq,
				    q_log_size, ele_log_size, &prq->wqe.wq,
				    &prq->wq_ctrl);
	if (ret)
		return ret;

	wq_sz = xsc_wq_cyc_get_size(&prq->wqe.wq);
	prq->wqe.di = kvzalloc_node(array_size(wq_sz, sizeof(*prq->wqe.di)),
				    GFP_KERNEL, cpu_to_node(c->cpu));
	if (!prq->wqe.di)
		goto err_destroy_wq;

	prq->wqe.wqe_bulk = PAGE_SIZE /
		roundup_pow_of_two(xsc_rx_get_linear_frag_sz(c->adapter->nic_param.mtu));

	pagepool_params.order = XSC_RX_FRAG_SZ_ORDER;
	pagepool_params.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV;
	pagepool_params.pool_size = wq_sz;
	pagepool_params.nid = cpu_to_node(c->cpu);
	pagepool_params.dev = c->adapter->dev;
	pagepool_params.dma_dir = DMA_FROM_DEVICE;
	pagepool_params.max_len = PAGE_SIZE;
	prq->page_pool = page_pool_create(&pagepool_params);
	if (IS_ERR(prq->page_pool)) {
		ret = PTR_ERR(prq->page_pool);
		prq->page_pool = NULL;
		goto err_free_di;
	}

	for (i = 0; i < wq_sz; i++) {
		struct xsc_eth_rx_wqe_cyc *wqe =
			xsc_wq_cyc_get_wqe(&prq->wqe.wq, i);

		wqe->data[0].data0 =
			cpu_to_le32(FIELD_PREP(XSC_WQE_DATA_SEG_DATA0_SEG_LEN_MASK,
					       prq_param->frag_size));
		wqe->data[0].mkey = cpu_to_le32(XSC_INVALID_LKEY);
	}

	prq->frag_size = prq_param->frag_size;

	return 0;

err_free_di:
	kvfree(prq->wqe.di);
err_destroy_wq:
	xsc_eth_wq_destroy(&prq->wq_ctrl);
	return ret;
}

static int xsc_eth_open_qp_rq(struct xsc_channel *c,
			      struct xsc_rq *prq,
			      struct xsc_rq_param *prq_param)
{
	struct xsc_core_device *xdev = c->adapter->xdev;
	struct xsc_create_qp_mbox_in *in;
	unsigned int hw_npages;
	u8 q_log_size;
	int inlen;
	int ret;

	ret = xsc_eth_alloc_rq(c, prq, prq_param);
	if (ret)
		return ret;

	q_log_size = prq_param->rq_attr.q_log_size;
	hw_npages = DIV_ROUND_UP(prq->wq_ctrl.buf.size, XSC_PAGE_SIZE_4K);
	inlen = sizeof(struct xsc_create_qp_mbox_in) +
		sizeof(__be64) * hw_npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto err_free_rq;
	}

	in->req.input_qpn = cpu_to_be16(0);
	in->req.qp_type = XSC_QUEUE_TYPE_RAW;
	in->req.log_rq_sz = ilog2(xdev->caps.recv_ds_num) + q_log_size;
	in->req.pa_num = cpu_to_be16(hw_npages);
	in->req.cqn_recv = cpu_to_be16(prq->cq.xcq.cqn);
	in->req.cqn_send = in->req.cqn_recv;
	in->req.glb_funcid = cpu_to_be16(xdev->glb_func_id);

	xsc_core_fill_page_frag_array(&prq->wq_ctrl.buf,
				      &in->req.pas[0], hw_npages);

	ret = xsc_core_eth_create_qp(xdev, in, inlen, &prq->rqn);
	kvfree(in);
	if (ret)
		goto err_free_rq;

	prq->cqp.qpn = prq->rqn;
	prq->cqp.event = xsc_eth_qp_event;
	prq->cqp.eth_queue_type = XSC_RES_RQ;

	ret = xsc_core_create_resource_common(xdev, &prq->cqp);
	if (ret) {
		netdev_err(c->adapter->netdev,
			   "create resource common error qp:%d errno:%d\n",
			   prq->rqn, ret);
		goto err_destroy_qp;
	}

	return 0;

err_destroy_qp:
	xsc_core_eth_destroy_qp(xdev, prq->rqn);
err_free_rq:
	xsc_eth_free_qp_rq(prq);
	return ret;
}

static void xsc_eth_close_qp_rq(struct xsc_channel *c, struct xsc_rq *prq)
{
	struct xsc_core_device *xdev = c->adapter->xdev;
	u32 wq_sz = xsc_wq_cyc_get_size(&prq->wqe.wq);
	u32 i;

	xsc_core_destroy_resource_common(xdev, &prq->cqp);

	/* If DESTROY_QP failed the RQ is still live in the firmware with its
	 * WQ pages posted; leak the WQ buffer and page_pool rather than return
	 * buffer pages the device can still DMA into.
	 */
	if (xsc_core_eth_destroy_qp(xdev, prq->cqp.qpn)) {
		netdev_err(c->adapter->netdev, "failed to close rq%d\n",
			   prq->cqp.qpn);
		return;
	}

	/* return the pages still posted to hardware before the pool dies */
	for (i = 0; i < wq_sz; i++)
		xsc_eth_dealloc_rx_wqe(prq, i);

	xsc_eth_free_qp_rq(prq);
}

static void xsc_eth_close_channel(struct xsc_channel *c, bool free_rq)
{
	netif_napi_del(&c->napi);

	if (free_rq)
		xsc_eth_close_qp_rq(c, &c->qp.rq);
	xsc_eth_close_cq(c, &c->qp.rq.cq);
	memset(&c->qp.rq, 0, sizeof(struct xsc_rq));

	xsc_eth_close_qp_sq(c, &c->qp.sq);
	xsc_eth_close_cq(c, &c->qp.sq.cq);
	memset(&c->qp.sq, 0, sizeof(struct xsc_sq));
}

static int xsc_eth_open_channels(struct xsc_adapter *adapter)
{
	struct xsc_channel_param *chl_param;
	bool free_rq = false;
	bool napi_enabled = false;
	int ret = 0;

	chl_param = kvzalloc_obj(*chl_param, GFP_KERNEL);
	if (!chl_param)
		return -ENOMEM;

	xsc_eth_build_channel_param(adapter, chl_param);

	ret = xsc_eth_open_channel(adapter, &adapter->channel, chl_param);
	if (ret)
		goto err_free_param;

	ret = xsc_eth_open_qp_rq(&adapter->channel, &adapter->channel.qp.rq,
				 &chl_param->rq_param);
	if (ret)
		goto err_close_channel;
	free_rq = true;

	napi_enable(&adapter->channel.napi);
	napi_enabled = true;

	ret = xsc_eth_modify_qps_channel(adapter, &adapter->channel);
	if (ret)
		goto err_close_channel;

	kvfree(chl_param);
	return 0;

err_close_channel:
	if (napi_enabled)
		napi_disable(&adapter->channel.napi);
	xsc_eth_close_channel(&adapter->channel, free_rq);
err_free_param:
	kvfree(chl_param);
	netdev_err(adapter->netdev, "failed to open channel, err=%d\n", ret);
	return ret;
}

static void xsc_eth_close_channels(struct xsc_adapter *adapter)
{
	xsc_eth_close_channel(&adapter->channel, true);
}

static void xsc_eth_activate_channel(struct xsc_channel *c)
{
	struct xsc_sq *psq = &c->qp.sq;

	psq->txq = netdev_get_tx_queue(c->netdev, 0);
	set_bit(XSC_ETH_SQ_STATE_ENABLED, &psq->state);
	netdev_tx_reset_queue(psq->txq);
	netif_tx_start_queue(psq->txq);

	set_bit(XSC_ETH_RQ_STATE_ENABLED, &c->qp.rq.state);
}

static void xsc_eth_deactivate_channel(struct xsc_channel *c)
{
	netif_tx_disable(c->netdev);

	clear_bit(XSC_ETH_RQ_STATE_ENABLED, &c->qp.rq.state);
	clear_bit(XSC_ETH_SQ_STATE_ENABLED, &c->qp.sq.state);

	synchronize_net();

	/* last doorbell out */
	napi_disable(&c->napi);
}

static int xsc_eth_sw_init(struct xsc_adapter *adapter)
{
	int ret;

	ret = xsc_eth_open_channels(adapter);
	if (ret)
		return ret;

	xsc_eth_activate_channel(&adapter->channel);

	return 0;
}

static void xsc_eth_sw_deinit(struct xsc_adapter *adapter)
{
	xsc_eth_deactivate_channel(&adapter->channel);
	xsc_eth_close_channels(adapter);
}

static int xsc_eth_get_link_status(struct xsc_adapter *adapter, bool *link_up)
{
	struct xsc_core_device *xdev = adapter->xdev;
	u8 state;
	int err;

	err = xsc_core_query_vport_state(xdev, 0, &state);
	if (err)
		return err;

	*link_up = state;
	return 0;
}

static int xsc_eth_change_link_status(struct xsc_adapter *adapter)
{
	bool link_up;
	int err;

	err = xsc_eth_get_link_status(adapter, &link_up);
	if (err) {
		netdev_err(adapter->netdev, "failed to query link status, err=%d\n",
			   err);
		return err;
	}

	if (link_up && !netif_carrier_ok(adapter->netdev)) {
		netdev_info(adapter->netdev, "Link up\n");
		netif_carrier_on(adapter->netdev);
	} else if (!link_up && netif_carrier_ok(adapter->netdev)) {
		netdev_info(adapter->netdev, "Link down\n");
		netif_carrier_off(adapter->netdev);
	}

	return 0;
}

/*
 * Registered with the PCI layer, which runs it on its own workqueue for
 * every XSC_CMD_EVENT_RESP_CHANGE_LINK event.
 */
static void xsc_eth_link_event_handler(void *arg)
{
	struct xsc_core_device *xdev = arg;
	struct xsc_adapter *adapter = xdev->eth_priv;
	int err;

	if (!adapter || !adapter->opened)
		return;

	err = xsc_eth_change_link_status(adapter);
	if (err)
		netdev_err(adapter->netdev, "failed to change linkstatus, err=%d\n",
			   err);
}

static bool xsc_get_pct_drop_config(struct xsc_core_device *xdev)
{
	return (xdev->pdev->device == XSC_MC_PF_DEV_ID) ||
		(xdev->pdev->device == XSC_MF_SOC_PF_DEV_ID) ||
		(xdev->pdev->device == XSC_MS_PF_DEV_ID) ||
		(xdev->pdev->device == XSC_MV_SOC_PF_DEV_ID);
}

static int xsc_eth_enable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_cmd_enable_nic_hca_mbox_out out = {};
	struct xsc_cmd_enable_nic_hca_mbox_in in = {};
	struct xsc_core_device *xdev = adapter->xdev;
	struct net_device *netdev = adapter->netdev;
	u16 caps_mask = 0;
	u16 caps = 0;
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_NIC_HCA);

	in.rss.rss_en = 1;
	in.rss.rqn_base = cpu_to_be16(adapter->channel.qp.rq.rqn);
	in.rss.rqn_num = cpu_to_be16(1);
	in.rss.hfunc = XSC_HASH_FUNC_TOP;
	in.rss.hash_tmpl = cpu_to_be32(XSC_HASH_IP_PORTS | XSC_HASH_IP6_PORTS);
	caps_mask |= BIT(XSC_TBM_CAP_RSS);
	caps_mask |= BIT(XSC_TBM_CAP_HASH_PPH);

	if (xsc_get_pct_drop_config(xdev))
		caps |= BIT(XSC_TBM_CAP_PCT_DROP_CONFIG);
	caps_mask |= BIT(XSC_TBM_CAP_PCT_DROP_CONFIG);

	memcpy(in.nic.mac_addr, netdev->dev_addr, ETH_ALEN);

	in.nic.caps = cpu_to_be16(caps);
	in.nic.caps_mask = cpu_to_be16(caps_mask);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		netdev_err(netdev, "failed!! err=%d, status=%d\n",
			   err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static int xsc_eth_disable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_cmd_disable_nic_hca_mbox_out out = {};
	struct xsc_cmd_disable_nic_hca_mbox_in in = {};
	struct xsc_core_device *xdev = adapter->xdev;
	struct net_device *netdev = adapter->netdev;
	u16 caps = 0;
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DISABLE_NIC_HCA);

	if (xsc_get_pct_drop_config(xdev))
		caps |= BIT(XSC_TBM_CAP_PCT_DROP_CONFIG);

	in.nic.caps = cpu_to_be16(caps);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		netdev_err(netdev, "failed!! err=%d, status=%d\n",
			   err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static void xsc_set_port_admin_status(struct xsc_adapter *adapter,
				      enum xsc_port_status status)
{
	struct xsc_event_set_port_admin_status_mbox_out out;
	struct xsc_event_set_port_admin_status_mbox_in in = {};
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_PORT_ADMIN_STATUS);
	in.status = cpu_to_be16(status);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		netdev_err(adapter->netdev,
			   "failed to set port admin status %s, err=%d\n",
			   status == XSC_PORT_UP ? "up" : "down", err);
}

static int xsc_eth_open(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	bool link_up;
	int ret;

	ret = xsc_eth_sw_init(adapter);
	if (ret)
		return ret;

	ret = xsc_eth_enable_nic_hca(adapter);
	if (ret)
		goto err_sw_deinit;

	ret = xsc_eth_get_link_status(adapter, &link_up);
	if (ret) {
		netdev_warn(netdev, "failed to query link status, err=%d\n", ret);
	} else if (link_up) {
		netdev_info(netdev, "Link up\n");
		netif_carrier_on(adapter->netdev);
	} else {
		netdev_info(netdev, "Link down\n");
	}

	adapter->opened = true;

	xsc_set_port_admin_status(adapter, XSC_PORT_UP);

	return 0;

err_sw_deinit:
	xsc_eth_sw_deinit(adapter);
	return ret;
}

static int xsc_eth_close(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int ret;

	adapter->opened = false;

	netif_carrier_off(adapter->netdev);

	xsc_eth_sw_deinit(adapter);

	ret = xsc_eth_disable_nic_hca(adapter);
	if (ret)
		netdev_err(adapter->netdev, "failed to disable nic hca, err=%d\n",
			   ret);

	xsc_set_port_admin_status(adapter, XSC_PORT_DOWN);

	return ret;
}

static int xsc_eth_set_hw_mtu(struct xsc_core_device *xdev,
			      u16 mtu, u16 rx_buf_sz)
{
	struct xsc_set_mtu_mbox_out out;
	struct xsc_set_mtu_mbox_in in;
	int err;

	memset(&in, 0, sizeof(struct xsc_set_mtu_mbox_in));
	memset(&out, 0, sizeof(struct xsc_set_mtu_mbox_out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_MTU);
	in.mtu = cpu_to_be16(mtu);
	in.rx_buf_sz_min = cpu_to_be16(rx_buf_sz);
	in.mac_port = xdev->mac_port;

	err = xsc_cmd_exec(xdev, &in, sizeof(struct xsc_set_mtu_mbox_in), &out,
			   sizeof(struct xsc_set_mtu_mbox_out));
	if (err) {
		netdev_err(xsc_dev_to_netdev(xdev),
			   "failed to set hw_mtu=%u rx_buf_sz=%u, err=%d, status=%d\n",
			   mtu, rx_buf_sz, err, out.hdr.status);
		return err;
	}

	return 0;
}

static const struct net_device_ops xsc_netdev_ops = {
	.ndo_open		= xsc_eth_open,
	.ndo_stop		= xsc_eth_close,
	.ndo_start_xmit		= xsc_eth_xmit,
};

static void xsc_eth_build_nic_netdev(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	netdev->netdev_ops = &xsc_netdev_ops;

	netdev->min_mtu = SW_DEFAULT_MTU;
	netdev->max_mtu = SW_DEFAULT_MTU;
	netdev->mtu = SW_DEFAULT_MTU;
}

static int xsc_eth_nic_init(struct xsc_adapter *adapter)
{
	xsc_eth_build_nic_params(adapter);
	xsc_eth_netdev_init(adapter);
	xsc_eth_build_nic_netdev(adapter);

	return 0;
}

static int xsc_eth_get_mac(struct xsc_core_device *xdev, char *mac)
{
	struct xsc_query_eth_mac_mbox_out *out;
	struct xsc_query_eth_mac_mbox_in in;
	int err;

	out = kzalloc_obj(*out, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_ETH_MAC);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), out, sizeof(*out));
	if (err || out->hdr.status) {
		netdev_warn(xsc_dev_to_netdev(xdev),
			    "get mac failed! err=%d, out.status=%u\n",
			    err, out->hdr.status);
		err = -ENOEXEC;
		goto exit;
	}

	ether_addr_copy(mac, out->mac);
	netdev_dbg(xsc_dev_to_netdev(xdev),
		   "get mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

exit:
	kfree(out);
	return err;
}

static void xsc_eth_l2_addr_init(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	char mac[6] = {0};
	int ret = 0;

	ret = xsc_eth_get_mac(adapter->xdev, mac);
	if (ret) {
		netdev_warn(netdev, "get mac failed %d, generate random mac...",
			    ret);
		eth_random_addr(mac);
		netdev->addr_assign_type = NET_ADDR_RANDOM;
	} else if (!is_valid_ether_addr(mac)) {
		netdev_warn(netdev, "invalid mac %pM from firmware, generate random mac...\n",
			    mac);
		eth_random_addr(mac);
		netdev->addr_assign_type = NET_ADDR_RANDOM;
	} else {
		netdev->addr_assign_type = NET_ADDR_PERM;
	}
	eth_hw_addr_set(netdev, mac);
}

static int xsc_eth_nic_enable(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;

	xsc_eth_l2_addr_init(adapter);

	return xsc_eth_set_hw_mtu(xdev, XSC_SW2HW_MTU(adapter->nic_param.mtu),
				  XSC_SW2HW_RX_PKT_LEN(adapter->nic_param.mtu));
}

static int xsc_eth_probe(struct auxiliary_device *adev,
			 const struct auxiliary_device_id *adev_id)
{
	struct xsc_adev *xsc_adev = container_of(adev, struct xsc_adev, adev);
	struct xsc_core_device *xdev = xsc_adev->xdev;
	struct xsc_adapter *adapter;
	struct net_device *netdev;
	int err;

	netdev = alloc_etherdev(sizeof(struct xsc_adapter));
	if (!netdev)
		return -ENOMEM;

	netdev->dev.parent = &xdev->pdev->dev;
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = xdev->pdev;
	adapter->dev = &adapter->pdev->dev;
	adapter->xdev = xdev;
	xdev->eth_priv = adapter;

	err = xsc_eth_nic_init(adapter);
	if (err) {
		netdev_err(netdev, "xsc_eth_nic_init failed, err=%d\n", err);
		goto err_free_netdev;
	}

	err = xsc_eth_nic_enable(adapter);
	if (err) {
		netdev_err(netdev, "xsc_eth_nic_enable failed, err=%d\n", err);
		goto err_free_netdev;
	}

	xsc_irq_event_register(xdev, xsc_eth_link_event_handler);

	err = register_netdev(netdev);
	if (err) {
		netdev_err(netdev, "register_netdev failed, err=%d\n", err);
		goto err_unregister_event;
	}

	return 0;

err_unregister_event:
	xsc_irq_event_unregister(xdev);
err_free_netdev:
	xdev->eth_priv = NULL;
	free_netdev(netdev);

	return err;
}

static void xsc_eth_remove(struct auxiliary_device *adev)
{
	struct xsc_adev *xsc_adev = container_of(adev, struct xsc_adev, adev);
	struct xsc_core_device *xdev = xsc_adev->xdev;
	struct xsc_adapter *adapter = xdev->eth_priv;

	/* Stop link events reaching this adapter and wait out one already in
	 * flight, which would otherwise touch the memory freed below.
	 */
	xsc_irq_event_unregister(xdev);

	/* Runs ndo_stop(), so the queues and the HCA are shut down first. */
	unregister_netdev(adapter->netdev);

	free_netdev(adapter->netdev);

	xdev->eth_priv = NULL;
}

static const struct auxiliary_device_id xsc_eth_id_table[] = {
	{ .name = XSC_PCI_DRV_NAME "." XSC_ETH_ADEV_NAME },
	{},
};
MODULE_DEVICE_TABLE(auxiliary, xsc_eth_id_table);

static struct auxiliary_driver xsc_eth_driver = {
	.name = "eth",
	.probe = xsc_eth_probe,
	.remove = xsc_eth_remove,
	.id_table = xsc_eth_id_table,
};
module_auxiliary_driver(xsc_eth_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Yunsilicon XSC ethernet driver");
