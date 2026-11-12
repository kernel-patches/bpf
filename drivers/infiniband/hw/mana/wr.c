// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */

#include "mana_ib.h"

#define MAX_WR_SGL_NUM (2)

static inline u32 mana_count_packets(u32 msg_size, enum ib_mtu mtu)
{
	return (msg_size - !!msg_size) >> (mtu + 7);
}

static inline bool wr_is_mmq(enum ib_wr_opcode opcode)
{
	switch (opcode) {
	case IB_WR_LOCAL_INV:
	case IB_WR_REG_MR:
	case IB_WR_REG_MR_INTEGRITY:
	case IB_WR_BIND_MW:
		return true;
	default:
		return false;
	}
}

static inline u8 convert_wr_to_wc(enum ib_wr_opcode opcode)
{
	switch (opcode) {
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_SEND_WITH_INV:
	case IB_WR_SEND:
		return IB_WC_SEND;
	case IB_WR_RDMA_WRITE_WITH_IMM:
	case IB_WR_RDMA_WRITE:
		return IB_WC_RDMA_WRITE;
	case IB_WR_RDMA_READ:
		return IB_WC_RDMA_READ;
	case IB_WR_LOCAL_INV:
		return IB_WC_LOCAL_INV;
	case IB_WR_BIND_MW:
		return IB_WC_BIND_MW;
	case IB_WR_REG_MR:
		return IB_WC_REG_MR;
	default:
		return 0;
	}
}

static inline u8 convert_wr_to_hw_opcode(enum ib_wr_opcode opcode)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
		return WQE_TYPE_WRITE;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return WQE_TYPE_WRITE_IMM;
	case IB_WR_SEND:
		return WQE_TYPE_RC_SEND;
	case IB_WR_SEND_WITH_IMM:
		return WQE_TYPE_RC_SEND_IMM;
	case IB_WR_SEND_WITH_INV:
		return WQE_TYPE_RC_SEND_INV;
	case IB_WR_LOCAL_INV:
		return WQE_TYPE_LOCAL_INV;
	case IB_WR_RDMA_READ:
		return WQE_TYPE_READ;
	case IB_WR_REG_MR:
		return WQE_TYPE_REG_MR;
	default:
		return 0;
	}
}

static int mana_ib_post_rq(struct mana_ib_qp *qp, const struct ib_recv_wr *wr)
{
	struct ib_sge mana_ib_dummy_sge = {.addr = 1, .length = 0, .lkey = 0};
	struct mana_ib_queue *ib_rq = mana_qp_get_rq(qp);
	struct gdma_posted_wqe_info wqe_info = {0};
	struct gdma_queue *queue = ib_rq->kmem;
	struct gdma_wqe_request wqe_req = {0};
	struct shadow_wqe_header *shadow_wqe;
	int err;

	if (shadow_queue_full(&qp->shadow_rq))
		return -EINVAL;

	if (wr->num_sge > MAX_RX_WQE_SGL_ENTRIES)
		return -EINVAL;

	wqe_req.num_sge = wr->num_sge;
	wqe_req.ib_sgl = wr->sg_list;
	wqe_req.flags = GDMA_WR_IB_SGL;

	if (wr->num_sge == 0) {
		wqe_req.ib_sgl = &mana_ib_dummy_sge;
		wqe_req.num_sge = 1;
	}

	err = mana_gd_post_work_request(queue, &wqe_req, &wqe_info);
	if (err)
		return err;

	shadow_wqe = shadow_queue_producer_entry(&qp->shadow_rq);
	memset(shadow_wqe, 0, sizeof(*shadow_wqe));
	shadow_wqe->wr_id = wr->wr_id;
	shadow_wqe->wqe_size_in_bu = wqe_info.wqe_size_in_bu;
	shadow_wqe->wqe_offset_or_psn = wqe_info.wqe_offset;
	shadow_queue_advance_producer(&qp->shadow_rq);

	return 0;
}

static int mana_ib_post_recv_ud(struct mana_ib_qp *qp, const struct ib_recv_wr *wr,
				const struct ib_recv_wr **bad_wr)
{
	struct mana_ib_dev *mdev = container_of(qp->ibqp.device, struct mana_ib_dev, ib_dev);
	struct mana_ib_queue *ib_rq = mana_qp_get_rq(qp);
	struct gdma_queue *rq = ib_rq->kmem;
	bool ring_rq = false;
	int err = 0;

	for (; wr; wr = wr->next) {
		err = mana_ib_post_rq(qp, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		ring_rq = true;
	}

	if (ring_rq)
		mana_gd_wq_ring_doorbell(mdev_to_gc(mdev), rq);

	return err;
}

static int mana_ib_post_recv_rc(struct mana_ib_qp *qp, const struct ib_recv_wr *wr,
				const struct ib_recv_wr **bad_wr)
{
	struct mana_ib_dev *mdev = container_of(qp->ibqp.device, struct mana_ib_dev, ib_dev);
	struct mana_ib_queue *ib_rq = mana_qp_get_rq(qp);
	unsigned long flags;
	u8 wqe_cnt = 0;
	int err = 0;

	spin_lock_irqsave(&qp->rq_lock, flags);

	for (; wr; wr = wr->next) {
		err = mana_ib_post_rq(qp, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		wqe_cnt++;
		if (wqe_cnt == 0xFF) {
			mana_gd_wq_ring_doorbell_ext(mdev_to_gc(mdev), ib_rq->kmem,
						     ib_rq->kmem->head * GDMA_WQE_BU_SIZE,
						     wqe_cnt, 0);
			wqe_cnt = 0;
		}
	}

	if (wqe_cnt)
		mana_gd_wq_ring_doorbell_ext(mdev_to_gc(mdev), ib_rq->kmem,
					     ib_rq->kmem->head * GDMA_WQE_BU_SIZE,
					     wqe_cnt, 0);

	spin_unlock_irqrestore(&qp->rq_lock, flags);
	return err;
}

int mana_ib_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr)
{
	struct mana_ib_qp *qp = container_of(ibqp, struct mana_ib_qp, ibqp);

	switch (ibqp->qp_type) {
	case IB_QPT_UD:
	case IB_QPT_GSI:
		return mana_ib_post_recv_ud(qp, wr, bad_wr);
	case IB_QPT_RC:
		return mana_ib_post_recv_rc(qp, wr, bad_wr);
	default:
		/* Unsupported QP type */
		*bad_wr = wr;
		return -EINVAL;
	}
}

static int mana_ib_post_send_ud_one(struct mana_ib_qp *qp, const struct ib_ud_wr *wr)
{
	struct mana_ib_dev *mdev = container_of(qp->ibqp.device, struct mana_ib_dev, ib_dev);
	struct mana_ib_ah *ah = container_of(wr->ah, struct mana_ib_ah, ibah);
	struct net_device *ndev = mana_ib_get_netdev(&mdev->ib_dev, qp->port);
	struct gdma_queue *queue = qp->ud_qp.queues[MANA_UD_SEND_QUEUE].kmem;
	struct gdma_sge gdma_sgl[MAX_WR_SGL_NUM + 1];
	struct gdma_posted_wqe_info wqe_info = {0};
	struct gdma_wqe_request wqe_req = {0};
	struct rdma_send_oob send_oob = {0};
	struct shadow_wqe_header *shadow_wqe;
	bool signaled = qp->sq_sig_all || (wr->wr.send_flags & IB_SEND_SIGNALED);
	int err, i;

	if (!ndev)
		return -EINVAL;

	if (wr->wr.opcode != IB_WR_SEND)
		return -EINVAL;

	if (shadow_queue_full(&qp->shadow_sq))
		return -EINVAL;

	if (wr->wr.num_sge > MAX_WR_SGL_NUM)
		return -EINVAL;

	gdma_sgl[0].address = ah->dma_handle;
	gdma_sgl[0].mem_key = qp->ibqp.pd->local_dma_lkey;
	gdma_sgl[0].size = sizeof(struct mana_ib_av);
	for (i = 0; i < wr->wr.num_sge; ++i) {
		gdma_sgl[i + 1].address = wr->wr.sg_list[i].addr;
		gdma_sgl[i + 1].mem_key = wr->wr.sg_list[i].lkey;
		gdma_sgl[i + 1].size = wr->wr.sg_list[i].length;
	}

	wqe_req.num_sge = wr->wr.num_sge + 1;
	wqe_req.sgl = gdma_sgl;
	wqe_req.inline_oob_size = INLINE_OOB_LARGE_SIZE;
	wqe_req.inline_oob_data = &send_oob;
	wqe_req.flags = GDMA_WR_OOB_IN_SGL;
	wqe_req.client_data_unit = ib_mtu_enum_to_int(ib_mtu_int_to_enum(ndev->mtu));

	send_oob.wqe_type = WQE_TYPE_UD_SEND;
	send_oob.fence = !!(wr->wr.send_flags & IB_SEND_FENCE);
	send_oob.signaled = signaled;
	send_oob.solicited = !!(wr->wr.send_flags & IB_SEND_SOLICITED);
	send_oob.psn = qp->sq_psn;
	send_oob.ssn_or_rqpn = wr->remote_qpn;
	send_oob.ud_send.remote_qkey =
		qp->ibqp.qp_type == IB_QPT_GSI ? IB_QP1_QKEY : wr->remote_qkey;

	err = mana_gd_post_work_request(queue, &wqe_req, &wqe_info);
	if (err)
		return err;

	qp->sq_psn++;
	shadow_wqe = shadow_queue_producer_entry(&qp->shadow_sq);
	memset(shadow_wqe, 0, sizeof(*shadow_wqe));
	shadow_wqe->wr_id = wr->wr.wr_id;
	shadow_wqe->flags = signaled ? 0 : MANA_WQ_NO_SIGNAL_WC;
	shadow_wqe->wqe_size_in_bu = wqe_info.wqe_size_in_bu;
	shadow_wqe->wqe_offset_or_psn = wqe_info.wqe_offset;
	shadow_queue_advance_producer(&qp->shadow_sq);

	return 0;
}

static int mana_ib_post_send_ud(struct mana_ib_qp *qp, const struct ib_send_wr *wr,
				const struct ib_send_wr **bad_wr)
{
	struct mana_ib_dev *mdev = container_of(qp->ibqp.device, struct mana_ib_dev, ib_dev);
	struct mana_ib_cq *cq = container_of(qp->ibqp.send_cq, struct mana_ib_cq, ibcq);
	struct gdma_queue *queue = qp->ud_qp.queues[MANA_UD_SEND_QUEUE].kmem;
	unsigned long flags;
	bool ring_sq = false;
	bool flush_send;
	int err = 0;

	for (; wr; wr = wr->next) {
		err = mana_ib_post_send_ud_one(qp, ud_wr(wr));
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		ring_sq = true;
	}

	if (ring_sq) {
		mana_gd_wq_ring_doorbell(mdev_to_gc(mdev), queue);

		spin_lock_irqsave(&cq->cq_lock, flags);
		flush_send = !list_empty(&qp->send_err_node);
		spin_unlock_irqrestore(&cq->cq_lock, flags);

		if (flush_send && cq->ibcq.comp_handler)
			cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
	}

	return err;
}

static int mana_ib_post_sq(struct mana_ib_qp *qp, const struct ib_send_wr *wr)
{
	struct gdma_queue *sq = qp->rc_qp.queues[MANA_RC_SEND_QUEUE_REQUESTER].kmem;
	struct ib_sge mana_ib_dummy_sge = {.addr = 1, .length = 0, .lkey = 0};
	struct gdma_posted_wqe_info wqe_info = {0};
	struct gdma_wqe_request wqe_req = {0};
	struct rdma_send_oob send_oob = {0};
	struct shadow_wqe_header *shadow_wqe;
	bool signaled = qp->sq_sig_all || (wr->send_flags & IB_SEND_SIGNALED);
	u32 msg_sz = 0;
	int err, i;

	if (shadow_queue_full(&qp->shadow_sq))
		return -ENOMEM;

	for (i = 0; i < wr->num_sge; i++)
		msg_sz += wr->sg_list[i].length;

	shadow_wqe = shadow_queue_producer_entry(&qp->shadow_sq);
	memset(shadow_wqe, 0, sizeof(*shadow_wqe));

	wqe_req.num_sge = wr->num_sge;
	wqe_req.ib_sgl = wr->sg_list;
	wqe_req.flags = GDMA_WR_IB_SGL;

	if (wr->num_sge == 0) {
		wqe_req.ib_sgl = &mana_ib_dummy_sge;
		wqe_req.num_sge = 1;
	}

	if (wr->opcode == IB_WR_RDMA_READ) {
		struct gdma_queue *rq = qp->rc_qp.queues[MANA_RC_RECV_QUEUE_REQUESTER].kmem;
		struct rdma_recv_oob recv_oob = {0};

		recv_oob.psn_start = qp->sq_psn;
		recv_oob.msn = qp->sq_ssn;

		wqe_req.inline_oob_size = INLINE_OOB_SMALL_SIZE;
		wqe_req.inline_oob_data = &recv_oob;
		wqe_req.flags |= GDMA_WR_CHECK_SN;

		err = mana_gd_post_work_request(rq, &wqe_req, &wqe_info);
		if (err)
			return err;

		/* For reads we store the WQE size of the receive WQE */
		shadow_wqe->wqe_size_in_bu = wqe_info.wqe_size_in_bu;

		/* SQ WQE for read uses dummy SGE */
		wqe_req.num_sge = 1;
		wqe_req.ib_sgl = &mana_ib_dummy_sge;
		wqe_req.flags = GDMA_WR_IB_SGL;
	}

	wqe_req.inline_oob_size = INLINE_OOB_EXTRA_LARGE_SIZE;
	wqe_req.inline_oob_data = &send_oob;
	wqe_req.client_data_unit = ib_mtu_enum_to_int(qp->mtu);
	wqe_req.flags |= GDMA_WR_GENERATION_1;
	wqe_req.wqe_size_in_bu = qp->rc_qp.wqe_size_in_bu;

	send_oob.wqe_type = convert_wr_to_hw_opcode(wr->opcode);
	send_oob.signaled = signaled;
	send_oob.solicited = !!(wr->send_flags & IB_SEND_SOLICITED);
	send_oob.psn = qp->sq_psn;
	send_oob.ssn_or_rqpn = qp->sq_ssn;

	if (qp->pending_mmq_fence) {
		/* set local fence */
		send_oob.fence = 1;
		send_oob.fsn = qp->sq_fsn;
		wqe_req.flags |= GDMA_WR_FENCE;
	}

	if (wr->send_flags & IB_SEND_FENCE) {
		/* add remote fence */
		if (qp->pending_mmq_fence)
			wqe_req.flags |= GDMA_WR_FENCE_EXTENDED;
		else
			wqe_req.flags |= GDMA_WR_FENCE;
	}

	switch (wr->opcode) {
	case IB_WR_SEND_WITH_INV:
		send_oob.rc_send.invalidate_key = wr->ex.invalidate_rkey;
		wqe_req.flags |= GDMA_WR_CHECK_SN;
		break;
	case IB_WR_SEND_WITH_IMM:
		send_oob.rc_send.immediate = cpu_to_le32(be32_to_cpu(wr->ex.imm_data));
		fallthrough;
	case IB_WR_SEND:
		wqe_req.flags |= GDMA_WR_CHECK_SN;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		send_oob.immediate_ext = cpu_to_le32(be32_to_cpu(wr->ex.imm_data));
		fallthrough;
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_READ:
		send_oob.rdma.address_hi = upper_32_bits(rdma_wr(wr)->remote_addr);
		send_oob.rdma.address_low = lower_32_bits(rdma_wr(wr)->remote_addr);
		send_oob.rdma.rkey = rdma_wr(wr)->rkey;
		send_oob.rdma.dma_len = msg_sz;
		if (wr->opcode == IB_WR_RDMA_READ) {
			send_oob.read.rsn = qp->sq_rsn;
			wqe_req.flags |= GDMA_WR_CHECK_RSN;
		} else {
			wqe_req.flags |= GDMA_WR_CHECK_SN;
		}
		break;
	default:
		return -EOPNOTSUPP;
	}

	err = mana_gd_post_work_request(sq, &wqe_req, &wqe_info);
	if (err)
		return err;

	shadow_wqe->wr_id = wr->wr_id;
	shadow_wqe->send_opcode = convert_wr_to_wc(wr->opcode);
	if (!signaled)
		shadow_wqe->flags |= MANA_WQ_NO_SIGNAL_WC;
	if ((wr->send_flags & IB_SEND_FENCE) || qp->pending_mmq_fence)
		shadow_wqe->flags |= MANA_WQ_FENCE_WC;
	shadow_wqe->wqe_offset_or_psn = qp->sq_psn + mana_count_packets(msg_sz, qp->mtu);
	shadow_wqe->fsn = qp->sq_fsn - 1;
	shadow_queue_advance_producer(&qp->shadow_sq);

	qp->pending_mmq_fence = false;
	qp->sq_psn = shadow_wqe->wqe_offset_or_psn + 1;
	qp->sq_ssn++;
	if (wr->opcode == IB_WR_RDMA_READ)
		qp->sq_rsn++;

	return 0;
}

static u8 mana_ib_fmr_access_flags(int ib_access_flags)
{
	u8 access = mana_ib_verbs_to_gdma_access_flags(ib_access_flags);

	return (access | GDMA_ACCESS_FLAG_INVALIDATE | GDMA_ACCESS_FLAG_FMR);
}

static void mana_ib_build_fmr_payload(const struct ib_reg_wr *wr, struct ib_sge *sge)
{
	struct mana_ib_mr *mr = container_of(wr->mr, struct mana_ib_mr, ibmr);
	u8 access = mana_ib_fmr_access_flags(wr->access);
	u8 *mst_base = (u8 *)mr->fmr.ptes;
	struct mana_fmr_mst_entry *mst;

	mst = (struct mana_fmr_mst_entry *)(mst_base +
		mana_ib_fmr_header_offset(mr->fmr.pte_count));
	memset(mst, 0, sizeof(struct mana_fmr_mst_entry));
	mst->access_right = access;
	mst->addr_type = GDMA_MR_TYPE_GVA;
	mst->start_va = wr->mr->iova;
	mst->length = wr->mr->length;
	mst->page_size = order_base_2(wr->mr->page_size) - MANA_PAGE_SHIFT;

	sge->addr = mr->fmr.dma_handle;
	sge->lkey = mr->ibmr.pd->local_dma_lkey;
	sge->length = mana_ib_fmr_buf_sz(mr->fmr.pte_count);
}

static int mana_ib_post_mmq(struct mana_ib_qp *qp, const struct ib_send_wr *wr)
{
	struct mana_ib_dev *mdev = container_of(qp->ibqp.device, struct mana_ib_dev, ib_dev);
	struct gdma_queue *queue = qp->rc_qp.queues[MANA_RC_SEND_QUEUE_MMQ].kmem;
	struct ib_sge sge = {.addr = 1, .length = 0, .lkey = 0};
	struct gdma_posted_wqe_info wqe_info = {0};
	struct gdma_wqe_request wqe_req = {0};
	struct rdma_send_oob send_oob = {0};
	struct shadow_wqe_header *shadow_wqe;
	bool signaled = qp->sq_sig_all || (wr->send_flags & IB_SEND_SIGNALED);
	int ret;

	if (shadow_queue_full(&qp->shadow_mmq))
		return -ENOMEM;

	shadow_wqe = shadow_queue_producer_entry(&qp->shadow_mmq);
	memset(shadow_wqe, 0, sizeof(*shadow_wqe));

	wqe_req.num_sge = 1;
	wqe_req.ib_sgl = &sge;
	wqe_req.flags = GDMA_WR_IB_SGL;

	wqe_req.inline_oob_size = INLINE_OOB_EXTRA_LARGE_SIZE;
	wqe_req.inline_oob_data = &send_oob;
	wqe_req.client_data_unit = 0;
	wqe_req.flags |= GDMA_WR_GENERATION_1;

	send_oob.wqe_type = convert_wr_to_hw_opcode(wr->opcode);
	send_oob.psn = qp->sq_fsn;
	send_oob.ssn_or_rqpn = qp->sq_ssn;
	send_oob.fsn = qp->sq_psn;
	send_oob.signaled = signaled;

	if (wr->send_flags & IB_SEND_FENCE)
		wqe_req.flags |= GDMA_WR_FENCE | GDMA_WR_FENCE_EXTENDED;

	switch (wr->opcode) {
	case IB_WR_LOCAL_INV:
		send_oob.mm.mkey = wr->ex.invalidate_rkey;
		break;
	case IB_WR_REG_MR:
		send_oob.mm.mkey = reg_wr(wr)->key;
		mana_ib_build_fmr_payload(reg_wr(wr), &sge);
		if (mdev->adapter_caps.feature_flags & MANA_IB_FEATURE_FMR_IN_OOB_SUPPORT)
			wqe_req.flags |= GDMA_WR_OOB_IN_SGL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = mana_gd_post_work_request(queue, &wqe_req, &wqe_info);
	if (ret)
		return ret;

	shadow_wqe->wr_id = wr->wr_id;
	shadow_wqe->send_opcode = convert_wr_to_wc(wr->opcode);
	if (!signaled)
		shadow_wqe->flags |= MANA_WQ_NO_SIGNAL_WC;
	if (wr->send_flags & IB_SEND_FENCE)
		shadow_wqe->flags |= MANA_WQ_FENCE_WC;
	shadow_wqe->wqe_size_in_bu = wqe_info.wqe_size_in_bu;
	shadow_wqe->wqe_offset_or_psn = qp->sq_psn - 1;
	shadow_wqe->fsn = qp->sq_fsn;

	shadow_queue_advance_producer(&qp->shadow_mmq);

	qp->sq_fsn++;
	qp->pending_mmq_fence = true;

	return 0;
}

static int mana_ib_post_send_rc(struct mana_ib_qp *qp, const struct ib_send_wr *wr,
				const struct ib_send_wr **bad_wr)
{
	struct mana_ib_dev *mdev = container_of(qp->ibqp.device, struct mana_ib_dev, ib_dev);
	bool ring_mmq = false, ring_sq = false, ring_rq = false;
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&qp->sq_lock, flags);

	for (; wr; wr = wr->next) {
		if (wr_is_mmq(wr->opcode)) {
			err = mana_ib_post_mmq(qp, wr);
			if (unlikely(err)) {
				*bad_wr = wr;
				break;
			}
			ring_mmq = true;
		} else {
			err = mana_ib_post_sq(qp, wr);
			if (unlikely(err)) {
				*bad_wr = wr;
				break;
			}
			if (wr->opcode == IB_WR_RDMA_READ)
				ring_rq = true;
			ring_sq = true;
		}
	}
	if (ring_rq)
		mana_gd_wq_ring_doorbell(mdev_to_gc(mdev),
					 qp->rc_qp.queues[MANA_RC_RECV_QUEUE_REQUESTER].kmem);
	if (ring_mmq)
		mana_gd_wq_ring_doorbell(mdev_to_gc(mdev),
					 qp->rc_qp.queues[MANA_RC_SEND_QUEUE_MMQ].kmem);
	if (ring_sq)
		mana_gd_wq_ring_doorbell(mdev_to_gc(mdev),
					 qp->rc_qp.queues[MANA_RC_SEND_QUEUE_REQUESTER].kmem);

	spin_unlock_irqrestore(&qp->sq_lock, flags);
	return err;
}

int mana_ib_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		      const struct ib_send_wr **bad_wr)
{
	struct mana_ib_qp *qp = container_of(ibqp, struct mana_ib_qp, ibqp);

	switch (ibqp->qp_type) {
	case IB_QPT_UD:
	case IB_QPT_GSI:
		return mana_ib_post_send_ud(qp, wr, bad_wr);
	case IB_QPT_RC:
		return mana_ib_post_send_rc(qp, wr, bad_wr);
	default:
		/* Unsupported QP type */
		*bad_wr = wr;
		return -EINVAL;
	}
}
