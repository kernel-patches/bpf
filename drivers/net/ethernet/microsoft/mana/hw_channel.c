// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021, Microsoft Corporation. */

#include <net/mana/gdma.h>
#include <net/mana/mana.h>
#include <net/mana/hw_channel.h>
#include <linux/vmalloc.h>

u32 mana_hwc_timeout_read(const struct hw_channel_context *hwc)
{
	return READ_ONCE(hwc->hwc_timeout);
}

void mana_hwc_timeout_update(struct hw_channel_context *hwc, u32 timeout_ms)
{
	u32 old_timeout;

	if (!timeout_ms)
		return;

	old_timeout = mana_hwc_timeout_read(hwc);
	while (old_timeout &&
	       cmpxchg(&hwc->hwc_timeout, old_timeout, timeout_ms) != old_timeout)
		old_timeout = mana_hwc_timeout_read(hwc);
}

void mana_hwc_timeout_cancel(struct hw_channel_context *hwc)
{
	xchg(&hwc->hwc_timeout, 0);
}

static void mana_hwc_timeout_reduce(struct hw_channel_context *hwc)
{
	u32 old_timeout = mana_hwc_timeout_read(hwc);

	while (old_timeout > 1 &&
	       cmpxchg(&hwc->hwc_timeout, old_timeout, 1) != old_timeout)
		old_timeout = mana_hwc_timeout_read(hwc);
}

static int mana_hwc_get_msg_index(struct hw_channel_context *hwc, u32 req_len,
				  void *resp, u32 resp_len,
				  struct hwc_caller_ctx **caller_ctx)
{
	struct gdma_resource *r = &hwc->inflight_msg_res;
	struct hwc_caller_ctx *ctx;
	unsigned long flags;
	u32 req_limit;
	u32 resp_limit;
	u32 wait_ms;
	u32 index;
	int err;

	req_limit = mana_hwc_get_max_req_size(hwc);
	resp_limit = min(hwc->rx_msg_size_limit, hwc->max_req_msg_size);
	if (req_len > req_limit || resp_len > resp_limit) {
		spin_lock_irqsave(&r->lock, flags);
		err = hwc->channel_up ? -EMSGSIZE : -ENODEV;
		spin_unlock_irqrestore(&r->lock, flags);

		if (err == -EMSGSIZE)
			dev_err(hwc->dev,
				"HWC: message sizes req=%u/%u resp=%u/%u exceed channel maxima\n",
				req_len, req_limit, resp_len, resp_limit);
		return err;
	}

	wait_ms = mana_hwc_timeout_read(hwc);
	if (down_timeout(&hwc->sema, msecs_to_jiffies(wait_ms))) {
		spin_lock_irqsave(&r->lock, flags);
		if (!hwc->channel_up)
			err = -ENODEV;
		else if (atomic_read(&hwc->abandoned_msgs))
			err = -ETIMEDOUT;
		else
			err = -EBUSY;
		spin_unlock_irqrestore(&r->lock, flags);

		return err;
	}

	spin_lock_irqsave(&r->lock, flags);
	if (!hwc->channel_up) {
		spin_unlock_irqrestore(&r->lock, flags);
		up(&hwc->sema);
		return -ENODEV;
	}

	/* The semaphore admits at most r->size holders at a time, so a slot
	 * acquired above always has a free bit waiting for it here.
	 */
	index = find_first_zero_bit(r->map, r->size);
	if (WARN_ON_ONCE(index >= r->size)) {
		spin_unlock_irqrestore(&r->lock, flags);
		up(&hwc->sema);
		return -EIO;
	}

	ctx = &hwc->caller_ctx[index];
	spin_lock(&ctx->lock);
	reinit_completion(&ctx->comp_event);
	/* Take both references (sender + response handler) before publishing
	 * the slot, so an early response cannot free it under the sender.
	 */
	refcount_set(&ctx->refcnt, 2);
	ctx->output_buf = resp;
	ctx->output_buflen = resp_len;
	ctx->error = -EINPROGRESS;
	ctx->status_code = 0;
	ctx->responded = false;
	ctx->resp_pending = true;
	ctx->msg_id = index;

	/* The response path takes r->lock before ctx->lock, so publishing the
	 * bitmap last makes every field above visible before it can consume
	 * the response-side reference.
	 */
	bitmap_set(r->map, index, 1);

	spin_unlock(&ctx->lock);
	spin_unlock_irqrestore(&r->lock, flags);

	*caller_ctx = ctx;

	return 0;
}

static void mana_hwc_put_msg_index(struct hw_channel_context *hwc, u16 msg_id)
{
	struct gdma_resource *r = &hwc->inflight_msg_res;
	unsigned long flags;

	spin_lock_irqsave(&r->lock, flags);
	bitmap_clear(r->map, msg_id, 1);
	spin_unlock_irqrestore(&r->lock, flags);

	up(&hwc->sema);
}

static void hwc_ctx_put(struct hw_channel_context *hwc,
			struct hwc_caller_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->refcnt))
		mana_hwc_put_msg_index(hwc, ctx->msg_id);
}

static bool mana_hwc_clear_resp_pending(struct hw_channel_context *hwc,
					struct hwc_caller_ctx *ctx)
{
	lockdep_assert_held(&ctx->lock);

	if (!ctx->resp_pending)
		return false;

	ctx->resp_pending = false;
	if (ctx->error == -ETIMEDOUT)
		atomic_dec(&hwc->abandoned_msgs);

	return true;
}

static int mana_hwc_verify_resp_msg(const struct hwc_caller_ctx *caller_ctx,
				    const struct gdma_resp_hdr *resp_msg,
				    u32 resp_len)
{
	if (resp_len < sizeof(*resp_msg))
		return -EPROTO;

	if (resp_len > caller_ctx->output_buflen)
		return -EPROTO;

	return 0;
}

static int mana_hwc_post_rx_wqe(const struct hwc_wq *hwc_rxq,
				struct hwc_work_request *req)
{
	struct device *dev = hwc_rxq->hwc->dev;
	struct gdma_sge *sge;
	int err;

	sge = &req->sge;
	sge->address = (u64)req->buf_sge_addr;
	sge->mem_key = hwc_rxq->msg_buf->gpa_mkey;
	sge->size = req->buf_len;

	memset(&req->wqe_req, 0, sizeof(struct gdma_wqe_request));
	req->wqe_req.sgl = sge;
	req->wqe_req.num_sge = 1;
	req->wqe_req.client_data_unit = 0;

	err = mana_gd_post_and_ring(hwc_rxq->gdma_wq, &req->wqe_req, NULL);
	if (err)
		dev_err(dev, "Failed to post WQE on HWC RQ: %d\n", err);
	return err;
}

static void mana_hwc_handle_resp(struct hw_channel_context *hwc, u32 resp_len,
				 struct hwc_work_request *rx_req, u16 msg_id)
{
	const struct gdma_resp_hdr *resp_msg = rx_req->buf_va;
	struct gdma_resource *r = &hwc->inflight_msg_res;
	struct hwc_caller_ctx *ctx;
	bool release;
	int err;

	spin_lock(&r->lock);
	if (!test_bit(msg_id, r->map)) {
		spin_unlock(&r->lock);
		dev_err(hwc->dev, "hwc_rx: invalid msg_id = %u\n", msg_id);
		mana_hwc_post_rx_wqe(hwc->rxq, rx_req);
		return;
	}

	ctx = hwc->caller_ctx + msg_id;
	spin_lock(&ctx->lock);
	spin_unlock(&r->lock);

	/* Consume the response-side reference exactly once. This releases a
	 * quarantined slot after its late response arrives.
	 */
	release = mana_hwc_clear_resp_pending(hwc, ctx);

	if (ctx->responded) {
		spin_unlock(&ctx->lock);
		mana_hwc_post_rx_wqe(hwc->rxq, rx_req);
		if (release)
			hwc_ctx_put(hwc, ctx);
		return;
	}
	ctx->responded = true;

	err = mana_hwc_verify_resp_msg(ctx, resp_msg, resp_len);
	if (!err) {
		ctx->status_code = resp_msg->status;
		memcpy(ctx->output_buf, resp_msg, resp_len);
	}
	ctx->error = err;

	/* Post RX WQE before completing; the next response may arrive
	 * immediately and needs a posted buffer.
	 */
	mana_hwc_post_rx_wqe(hwc->rxq, rx_req);
	complete(&ctx->comp_event);
	spin_unlock(&ctx->lock);

	if (release)
		hwc_ctx_put(hwc, ctx);
}

static void mana_hwc_init_event_handler(void *ctx, struct gdma_queue *q_self,
					struct gdma_event *event)
{
	union hwc_init_soc_service_type service_data;
	struct hw_channel_context *hwc = ctx;
	struct gdma_dev *gd = hwc->gdma_dev;
	union hwc_init_type_data type_data;
	union hwc_init_eq_id_db eq_db;
	struct mana_context *ac;
	u32 type, val;
	int ret;

	switch (event->type) {
	case GDMA_EQE_HWC_INIT_EQ_ID_DB:
		eq_db.as_uint32 = event->details[0];
		if (!mana_gd_is_valid_doorbell(gd->gdma_context,
					       eq_db.doorbell)) {
			dev_err(hwc->dev, "HWC: invalid doorbell %u\n",
				eq_db.doorbell);
			WRITE_ONCE(hwc->hwc_init_error, -EPROTO);
			complete(&hwc->hwc_init_eqe_comp);
			break;
		}

		hwc->cq->gdma_eq->id = eq_db.eq_id;
		gd->doorbell = eq_db.doorbell;
		hwc->hwc_init_doorbell = true;
		break;

	case GDMA_EQE_HWC_INIT_DATA:
		type_data.as_uint32 = event->details[0];
		type = type_data.type;
		val = type_data.value;

		switch (type) {
		case HWC_INIT_DATA_CQID:
			WRITE_ONCE(hwc->hwc_init_cq_id, val);
			break;

		case HWC_INIT_DATA_RQID:
			hwc->rxq->gdma_wq->id = val;
			break;

		case HWC_INIT_DATA_SQID:
			hwc->txq->gdma_wq->id = val;
			break;

		case HWC_INIT_DATA_QUEUE_DEPTH:
			/* Preserve the full 24-bit report for validation. */
			hwc->hwc_init_q_depth_max = val;
			break;

		case HWC_INIT_DATA_MAX_REQUEST:
			hwc->hwc_init_max_req_msg_size = val;
			break;

		case HWC_INIT_DATA_MAX_RESPONSE:
			hwc->hwc_init_max_resp_msg_size = val;
			break;

		case HWC_INIT_DATA_MAX_NUM_CQS:
			/* Store only; establish_channel() commits it to
			 * max_num_cqs once, so a later event cannot grow the
			 * bound past the allocation.  Pairs with its READ_ONCE().
			 */
			WRITE_ONCE(hwc->hwc_init_max_num_cqs, val);
			break;

		case HWC_INIT_DATA_PDID:
			hwc->gdma_dev->pdid = val;
			break;

		case HWC_INIT_DATA_GPA_MKEY:
			hwc->rxq->msg_buf->gpa_mkey = val;
			hwc->txq->msg_buf->gpa_mkey = val;
			break;

		case HWC_INIT_DATA_DEST_RQ_ID:
			hwc->dest_vrq_id = val;
			break;

		case HWC_INIT_DATA_DEST_CQ_ID:
			hwc->dest_vrcq_id = val;
			break;
		}

		break;

	case GDMA_EQE_HWC_INIT_DONE:
		complete(&hwc->hwc_init_eqe_comp);
		break;

	case GDMA_EQE_HWC_SOC_RECONFIG_DATA:
		type_data.as_uint32 = event->details[0];
		type = type_data.type;
		val = type_data.value;

		switch (type) {
		case HWC_DATA_CFG_HWC_TIMEOUT:
			mana_hwc_timeout_update(hwc, val);
			break;

		case HWC_DATA_HW_LINK_CONNECT:
		case HWC_DATA_HW_LINK_DISCONNECT:
			ac = gd->gdma_context->mana.driver_data;
			if (!ac)
				break;

			WRITE_ONCE(ac->link_event, type);
			schedule_work(&ac->link_change_work);

			break;

		default:
			dev_warn(hwc->dev, "Received unknown reconfig type %u\n", type);
			break;
		}

		break;
	case GDMA_EQE_HWC_SOC_SERVICE:
		service_data.as_uint32 = event->details[0];
		type = service_data.type;

		switch (type) {
		case GDMA_SERVICE_TYPE_RDMA_SUSPEND:
		case GDMA_SERVICE_TYPE_RDMA_RESUME:
			ret = mana_rdma_service_event(gd->gdma_context, type);
			if (ret)
				dev_err(hwc->dev, "Failed to schedule adev service event: %d\n",
					ret);
			break;
		default:
			dev_warn(hwc->dev, "Received unknown SOC service type %u\n", type);
			break;
		}

		break;
	default:
		dev_warn(hwc->dev, "Received unknown gdma event %u\n", event->type);
		/* Ignore unknown events, which should never happen. */
		break;
	}
}

static void mana_hwc_rx_event_handler(void *ctx, u32 gdma_rxq_id,
				      const struct hwc_rx_oob *rx_oob)
{
	struct hw_channel_context *hwc = ctx;
	struct hwc_wq *hwc_rxq = hwc->rxq;
	struct hwc_work_request *rx_req;
	struct gdma_resp_hdr *resp;
	struct gdma_wqe *dma_oob;
	struct gdma_queue *rq;
	struct gdma_sge *sge;
	u64 rq_base_addr;
	u64 rx_req_idx;
	u16 msg_id;
	u8 *wqe;

	if (WARN_ON_ONCE(hwc_rxq->gdma_wq->id != gdma_rxq_id))
		return;

	rq = hwc_rxq->gdma_wq;
	wqe = mana_gd_get_wqe_ptr(rq, rx_oob->wqe_offset / GDMA_WQE_BU_SIZE);
	dma_oob = (struct gdma_wqe *)wqe;

	sge = (struct gdma_sge *)(wqe + 8 + dma_oob->inline_oob_size_div4 * 4);

	/* Select the RX work request for virtual address and for reposting. */
	rq_base_addr = hwc_rxq->msg_buf->mem_info.dma_handle;
	rx_req_idx = (sge->address - rq_base_addr) / hwc->max_req_msg_size;

	if (rx_req_idx >= hwc_rxq->msg_buf->num_reqs) {
		dev_err(hwc->dev, "HWC RX: wrong rx_req_idx=%llu, num_reqs=%u\n",
			rx_req_idx, hwc_rxq->msg_buf->num_reqs);
		return;
	}

	rx_req = &hwc_rxq->msg_buf->reqs[rx_req_idx];
	resp = (struct gdma_resp_hdr *)rx_req->buf_va;

	/* Read msg_id once from DMA buffer to prevent TOCTOU:
	 * DMA memory is shared/unencrypted in CVMs - host can
	 * modify it between reads.
	 */
	msg_id = READ_ONCE(resp->response.hwc_msg_id);
	if (msg_id >= hwc->num_inflight_msg) {
		dev_err(hwc->dev, "HWC RX: wrong msg_id=%u\n", msg_id);
		return;
	}

	mana_hwc_handle_resp(hwc, rx_oob->tx_oob_data_size, rx_req, msg_id);

	/* Can no longer use 'resp', because the buffer is posted to the HW
	 * in mana_hwc_handle_resp() above.
	 */
	resp = NULL;
}

static void mana_hwc_tx_event_handler(void *ctx, u32 gdma_txq_id,
				      const struct hwc_rx_oob *rx_oob)
{
	struct hw_channel_context *hwc = ctx;
	struct hwc_wq *hwc_txq = hwc->txq;

	WARN_ON_ONCE(!hwc_txq || hwc_txq->gdma_wq->id != gdma_txq_id);
}

static int mana_hwc_create_gdma_wq(struct hw_channel_context *hwc,
				   enum gdma_queue_type type, u64 queue_size,
				   struct gdma_queue **queue)
{
	struct gdma_queue_spec spec = {};

	if (type != GDMA_SQ && type != GDMA_RQ)
		return -EINVAL;

	spec.type = type;
	spec.monitor_avl_buf = false;
	spec.queue_size = queue_size;

	return mana_gd_create_hwc_queue(hwc->gdma_dev, &spec, queue);
}

static int mana_hwc_create_gdma_cq(struct hw_channel_context *hwc,
				   u64 queue_size,
				   void *ctx, gdma_cq_callback *cb,
				   struct gdma_queue *parent_eq,
				   struct gdma_queue **queue)
{
	struct gdma_queue_spec spec = {};

	spec.type = GDMA_CQ;
	spec.monitor_avl_buf = false;
	spec.queue_size = queue_size;
	spec.cq.context = ctx;
	spec.cq.callback = cb;
	spec.cq.parent_eq = parent_eq;

	return mana_gd_create_hwc_queue(hwc->gdma_dev, &spec, queue);
}

static int mana_hwc_create_gdma_eq(struct hw_channel_context *hwc,
				   u64 queue_size,
				   void *ctx, gdma_eq_callback *cb,
				   struct gdma_queue **queue)
{
	struct gdma_queue_spec spec = {};

	spec.type = GDMA_EQ;
	spec.monitor_avl_buf = false;
	spec.queue_size = queue_size;
	spec.eq.context = ctx;
	spec.eq.callback = cb;
	spec.eq.log2_throttle_limit = DEFAULT_LOG2_THROTTLING_FOR_ERROR_EQ;
	spec.eq.msix_index = 0;

	return mana_gd_create_hwc_queue(hwc->gdma_dev, &spec, queue);
}

static void mana_hwc_comp_event(void *ctx, struct gdma_queue *q_self)
{
	struct hwc_rx_oob comp_data = {};
	struct gdma_comp *completions;
	struct hwc_cq *hwc_cq = ctx;
	int comp_read, i;

	WARN_ON_ONCE(hwc_cq->gdma_cq != q_self);

	completions = hwc_cq->comp_buf;
	comp_read = mana_gd_poll_cq(q_self, completions, hwc_cq->queue_depth);
	WARN_ON_ONCE(comp_read <= 0 || comp_read > hwc_cq->queue_depth);

	for (i = 0; i < comp_read; ++i) {
		comp_data = *(struct hwc_rx_oob *)completions[i].cqe_data;

		if (completions[i].is_sq)
			hwc_cq->tx_event_handler(hwc_cq->tx_event_ctx,
						completions[i].wq_num,
						&comp_data);
		else
			hwc_cq->rx_event_handler(hwc_cq->rx_event_ctx,
						completions[i].wq_num,
						&comp_data);
	}

	mana_gd_ring_cq(q_self, SET_ARM_BIT);
}

static int mana_hwc_publish_cq(struct gdma_context *gc,
			       struct gdma_queue *cq)
{
	struct gdma_queue **cq_table = READ_ONCE(gc->cq_table);
	u32 id = READ_ONCE(cq->id);

	if (!cq_table || id >= READ_ONCE(gc->max_num_cqs) ||
	    READ_ONCE(cq_table[id]))
		return -EINVAL;

	WRITE_ONCE(cq_table[id], cq);

	return 0;
}

static void mana_hwc_unpublish_cq(struct gdma_context *gc,
				  struct gdma_queue *cq)
{
	struct gdma_queue **cq_table = READ_ONCE(gc->cq_table);
	u32 id;

	if (!cq_table || !cq)
		return;

	id = READ_ONCE(cq->id);
	if (id < READ_ONCE(gc->max_num_cqs) &&
	    READ_ONCE(cq_table[id]) == cq)
		WRITE_ONCE(cq_table[id], NULL);
}

static void mana_hwc_destroy_cq(struct gdma_context *gc, struct hwc_cq *hwc_cq)
{
	/* Destroy the EQ first: it deregisters the IRQ and drains in-flight
	 * handlers, so none can touch the CQ after it is freed.
	 */
	if (hwc_cq->gdma_eq)
		mana_gd_destroy_queue(gc, hwc_cq->gdma_eq);

	/* Safe to free now that the EQ handler is fenced. */
	if (hwc_cq->gdma_cq)
		mana_gd_destroy_queue(gc, hwc_cq->gdma_cq);

	kfree(hwc_cq->comp_buf);
	kfree(hwc_cq);
}

static int mana_hwc_create_cq(struct hw_channel_context *hwc, u16 q_depth,
			      gdma_eq_callback *callback, void *ctx,
			      hwc_rx_event_handler_t *rx_ev_hdlr,
			      void *rx_ev_ctx,
			      hwc_tx_event_handler_t *tx_ev_hdlr,
			      void *tx_ev_ctx, struct hwc_cq **hwc_cq_ptr)
{
	struct gdma_queue *eq, *cq;
	struct gdma_comp *comp_buf;
	struct hwc_cq *hwc_cq;
	u32 eq_size, cq_size;
	int err;

	eq_size = roundup_pow_of_two(GDMA_EQE_SIZE * q_depth);
	if (eq_size < MANA_MIN_QSIZE)
		eq_size = MANA_MIN_QSIZE;

	cq_size = roundup_pow_of_two(GDMA_CQE_SIZE * q_depth);
	if (cq_size < MANA_MIN_QSIZE)
		cq_size = MANA_MIN_QSIZE;

	hwc_cq = kzalloc_obj(*hwc_cq);
	if (!hwc_cq)
		return -ENOMEM;

	err = mana_hwc_create_gdma_eq(hwc, eq_size, ctx, callback, &eq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC EQ for RQ: %d\n", err);
		goto out;
	}
	hwc_cq->gdma_eq = eq;

	err = mana_hwc_create_gdma_cq(hwc, cq_size, hwc_cq, mana_hwc_comp_event,
				      eq, &cq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC CQ for RQ: %d\n", err);
		goto out;
	}
	hwc_cq->gdma_cq = cq;

	comp_buf = kzalloc_objs(*comp_buf, q_depth);
	if (!comp_buf) {
		err = -ENOMEM;
		goto out;
	}

	hwc_cq->hwc = hwc;
	hwc_cq->comp_buf = comp_buf;
	hwc_cq->queue_depth = q_depth;
	hwc_cq->rx_event_handler = rx_ev_hdlr;
	hwc_cq->rx_event_ctx = rx_ev_ctx;
	hwc_cq->tx_event_handler = tx_ev_hdlr;
	hwc_cq->tx_event_ctx = tx_ev_ctx;

	*hwc_cq_ptr = hwc_cq;
	return 0;
out:
	mana_hwc_destroy_cq(hwc->gdma_dev->gdma_context, hwc_cq);
	return err;
}

static int mana_hwc_alloc_dma_buf(struct hw_channel_context *hwc, u16 q_depth,
				  u32 max_msg_size,
				  struct hwc_dma_buf **dma_buf_ptr)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	struct hwc_work_request *hwc_wr;
	struct hwc_dma_buf *dma_buf;
	struct gdma_mem_info *gmi;
	void *virt_addr;
	u32 buf_size;
	u8 *base_pa;
	int err;
	u16 i;

	dma_buf = kzalloc_flex(*dma_buf, reqs, q_depth);
	if (!dma_buf)
		return -ENOMEM;

	dma_buf->num_reqs = q_depth;

	/* mana_gd_alloc_memory() requires a power-of-two length. */
	buf_size = roundup_pow_of_two(MANA_PAGE_ALIGN(q_depth * max_msg_size));

	gmi = &dma_buf->mem_info;
	err = mana_gd_alloc_memory(gc, buf_size, gmi, false);
	if (err) {
		dev_err(hwc->dev, "Failed to allocate DMA buffer size: %u, err %d\n",
			buf_size, err);
		goto out;
	}

	virt_addr = dma_buf->mem_info.virt_addr;
	base_pa = (u8 *)dma_buf->mem_info.dma_handle;

	for (i = 0; i < q_depth; i++) {
		hwc_wr = &dma_buf->reqs[i];

		hwc_wr->buf_va = virt_addr + i * max_msg_size;
		hwc_wr->buf_sge_addr = base_pa + i * max_msg_size;

		hwc_wr->buf_len = max_msg_size;
	}

	*dma_buf_ptr = dma_buf;
	return 0;
out:
	kfree(dma_buf);
	return err;
}

static void mana_hwc_dealloc_dma_buf(struct hw_channel_context *hwc,
				     struct hwc_dma_buf *dma_buf)
{
	if (!dma_buf)
		return;

	mana_gd_free_memory(&dma_buf->mem_info);

	kfree(dma_buf);
}

static void mana_hwc_destroy_wq(struct hw_channel_context *hwc,
				struct hwc_wq *hwc_wq)
{
	mana_hwc_dealloc_dma_buf(hwc, hwc_wq->msg_buf);

	if (hwc_wq->gdma_wq)
		mana_gd_destroy_queue(hwc->gdma_dev->gdma_context,
				      hwc_wq->gdma_wq);

	kfree(hwc_wq);
}

static int mana_hwc_create_wq(struct hw_channel_context *hwc,
			      enum gdma_queue_type q_type, u16 q_depth,
			      u32 max_msg_size, struct hwc_cq *hwc_cq,
			      struct hwc_wq **hwc_wq_ptr)
{
	struct gdma_queue *queue;
	struct hwc_wq *hwc_wq;
	u32 queue_size;
	int err;

	WARN_ON(q_type != GDMA_SQ && q_type != GDMA_RQ);

	if (q_type == GDMA_RQ)
		queue_size = roundup_pow_of_two(GDMA_MAX_RQE_SIZE * q_depth);
	else
		queue_size = roundup_pow_of_two(GDMA_MAX_SQE_SIZE * q_depth);

	if (queue_size < MANA_MIN_QSIZE)
		queue_size = MANA_MIN_QSIZE;

	hwc_wq = kzalloc_obj(*hwc_wq);
	if (!hwc_wq)
		return -ENOMEM;

	err = mana_hwc_create_gdma_wq(hwc, q_type, queue_size, &queue);
	if (err)
		goto out;

	hwc_wq->hwc = hwc;
	hwc_wq->gdma_wq = queue;
	hwc_wq->queue_depth = q_depth;
	hwc_wq->hwc_cq = hwc_cq;
	spin_lock_init(&hwc_wq->lock);

	err = mana_hwc_alloc_dma_buf(hwc, q_depth, max_msg_size,
				     &hwc_wq->msg_buf);
	if (err)
		goto out;

	*hwc_wq_ptr = hwc_wq;
	return 0;
out:
	if (err)
		mana_hwc_destroy_wq(hwc, hwc_wq);

	dev_err(hwc->dev, "Failed to create HWC queue size= %u type= %d err= %d\n",
		queue_size, q_type, err);
	return err;
}

static int mana_hwc_post_tx_wqe(struct hwc_wq *hwc_txq,
				struct hwc_work_request *req,
				u32 dest_virt_rq_id, u32 dest_virt_rcq_id,
				bool dest_pf)
{
	struct device *dev = hwc_txq->hwc->dev;
	struct hwc_tx_oob *tx_oob;
	struct gdma_sge *sge;
	int err;

	if (req->msg_size == 0 || req->msg_size > req->buf_len) {
		dev_err(dev, "wrong msg_size: %u, buf_len: %u\n",
			req->msg_size, req->buf_len);
		return -EINVAL;
	}

	tx_oob = &req->tx_oob;

	tx_oob->vrq_id = dest_virt_rq_id;
	tx_oob->dest_vfid = 0;
	tx_oob->vrcq_id = dest_virt_rcq_id;
	tx_oob->vscq_id = hwc_txq->hwc_cq->gdma_cq->id;
	tx_oob->loopback = false;
	tx_oob->lso_override = false;
	tx_oob->dest_pf = dest_pf;
	tx_oob->vsq_id = hwc_txq->gdma_wq->id;

	sge = &req->sge;
	sge->address = (u64)req->buf_sge_addr;
	sge->mem_key = hwc_txq->msg_buf->gpa_mkey;
	sge->size = req->msg_size;

	memset(&req->wqe_req, 0, sizeof(struct gdma_wqe_request));
	req->wqe_req.sgl = sge;
	req->wqe_req.num_sge = 1;
	req->wqe_req.inline_oob_size = sizeof(struct hwc_tx_oob);
	req->wqe_req.inline_oob_data = tx_oob;
	req->wqe_req.client_data_unit = 0;

	spin_lock(&hwc_txq->lock);
	err = mana_gd_post_and_ring(hwc_txq->gdma_wq, &req->wqe_req, NULL);
	spin_unlock(&hwc_txq->lock);

	if (err)
		dev_err(dev, "Failed to post WQE on HWC SQ: %d\n", err);
	return err;
}

static int mana_hwc_init_inflight_msg(struct hw_channel_context *hwc,
				      u16 num_msg)
{
	int err;

	atomic_set(&hwc->abandoned_msgs, 0);
	sema_init(&hwc->sema, num_msg);

	err = mana_gd_alloc_res_map(num_msg, &hwc->inflight_msg_res);
	if (err)
		dev_err(hwc->dev, "Failed to init inflight_msg_res: %d\n", err);
	return err;
}

static int mana_hwc_test_channel(struct hw_channel_context *hwc)
{
	struct hwc_wq *hwc_rxq = hwc->rxq;
	struct hwc_work_request *req;
	struct hwc_caller_ctx *ctx;
	unsigned long flags;
	int err;
	int i;

	/* Post all WQEs on the RQ */
	for (i = 0; i < hwc->num_inflight_msg; i++) {
		req = &hwc_rxq->msg_buf->reqs[i];
		err = mana_hwc_post_rx_wqe(hwc_rxq, req);
		if (err)
			return err;
	}

	ctx = kzalloc_objs(*ctx, hwc->num_inflight_msg);
	if (!ctx)
		return -ENOMEM;

	for (i = 0; i < hwc->num_inflight_msg; ++i) {
		init_completion(&ctx[i].comp_event);
		spin_lock_init(&ctx[i].lock);
	}

	hwc->caller_ctx = ctx;

	/* Setup owns hwc directly; runtime publication follows this test. */
	spin_lock_irqsave(&hwc->inflight_msg_res.lock, flags);
	hwc->channel_up = true;
	spin_unlock_irqrestore(&hwc->inflight_msg_res.lock, flags);

	err = mana_gd_test_hwc_eq(hwc, hwc->cq->gdma_eq);
	if (err) {
		spin_lock_irqsave(&hwc->inflight_msg_res.lock, flags);
		hwc->channel_up = false;
		spin_unlock_irqrestore(&hwc->inflight_msg_res.lock, flags);
	}

	return err;
}

struct mana_hwc_init_report {
	u32 queue_depth;
	u32 max_req_msg_size;
	u32 max_resp_msg_size;
};

static int
mana_hwc_establish_channel(struct hw_channel_context *hwc,
			   struct mana_hwc_init_report *report)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	struct gdma_queue *rq = hwc->rxq->gdma_wq;
	struct gdma_queue *sq = hwc->txq->gdma_wq;
	struct gdma_queue *eq = hwc->cq->gdma_eq;
	struct gdma_queue *cq = hwc->cq->gdma_cq;
	struct gdma_queue **cq_table;
	u32 num_cqs;
	u32 cq_id;
	int err;

	hwc->hwc_init_q_depth_max = 0;
	hwc->hwc_init_max_req_msg_size = 0;
	hwc->hwc_init_max_resp_msg_size = 0;
	hwc->hwc_init_max_num_cqs = 0;
	hwc->hwc_init_cq_id = 0;
	hwc->hwc_init_doorbell = false;
	WRITE_ONCE(hwc->hwc_init_error, 0);
	gc->hwc.pdid = INVALID_PDID;
	/* Re-establish must not rearm through the previous channel's doorbell. */
	gc->hwc.doorbell = INVALID_DOORBELL;
	hwc->dest_vrq_id = 0;
	hwc->dest_vrcq_id = 0;

	init_completion(&hwc->hwc_init_eqe_comp);

	err = mana_smc_setup_hwc(&gc->shm_channel, false,
				 eq->mem_info.dma_handle,
				 cq->mem_info.dma_handle,
				 rq->mem_info.dma_handle,
				 sq->mem_info.dma_handle,
				 eq->eq.msix_index, &hwc->setup_active);
	if (err)
		return err;

	if (!wait_for_completion_timeout(&hwc->hwc_init_eqe_comp, 60 * HZ))
		return -ETIMEDOUT;

	err = READ_ONCE(hwc->hwc_init_error);
	if (err)
		return err;

	if (!hwc->hwc_init_doorbell) {
		dev_err(hwc->dev, "HWC: missing valid doorbell in init data\n");
		return -EPROTO;
	}

	report->queue_depth = hwc->hwc_init_q_depth_max;
	report->max_req_msg_size = hwc->hwc_init_max_req_msg_size;
	report->max_resp_msg_size = hwc->hwc_init_max_resp_msg_size;

	/* Snapshot the device-reported count and id once, so the same value
	 * sizes, bounds and indexes cq_table even across the sleeping
	 * vcalloc() and a concurrent init event.
	 */
	num_cqs = READ_ONCE(hwc->hwc_init_max_num_cqs);
	cq_id = READ_ONCE(hwc->hwc_init_cq_id);

	/* Both operands come from untrusted HWC bootstrap events; a missing
	 * MAX_NUM_CQS leaves num_cqs at 0.  Reject rather than WARN_ON() so a
	 * malformed device response cannot panic a panic_on_warn guest.
	 */
	if (cq_id >= num_cqs) {
		dev_err_ratelimited(hwc->dev,
				    "HWC: bad CQ id %u >= max %u\n",
				    cq_id, num_cqs);
		return -EPROTO;
	}

	/* Init events remain enabled, so commit the validated CQ ID once. */
	WRITE_ONCE(cq->id, cq_id);

	cq_table = vcalloc(num_cqs, sizeof(*cq_table));
	if (!cq_table)
		return -ENOMEM;

	/* Publish the bound and the initialised table together; the release
	 * pairs with smp_load_acquire() in mana_gd_process_eqe().
	 */
	WRITE_ONCE(gc->max_num_cqs, num_cqs);
	/* Pairs with smp_load_acquire() in mana_gd_process_eqe(). */
	smp_store_release(&gc->cq_table, cq_table);

	err = mana_hwc_publish_cq(gc, cq);
	if (err) {
		dev_err_ratelimited(hwc->dev,
				    "HWC: failed to publish CQ %u: %d\n",
				    cq_id, err);
		return err;
	}

	return 0;
}

static int mana_hwc_init_queues(struct hw_channel_context *hwc, u16 q_depth,
				u32 max_req_msg_size, u32 max_resp_msg_size)
{
	int err;

	if (q_depth > U16_MAX / 2)
		return -EINVAL;

	err = mana_hwc_init_inflight_msg(hwc, q_depth);
	if (err)
		return err;

	/* CQ is shared by SQ and RQ, so CQ's queue depth is the sum of SQ
	 * queue depth and RQ queue depth.
	 */
	err = mana_hwc_create_cq(hwc, q_depth * 2,
				 mana_hwc_init_event_handler, hwc,
				 mana_hwc_rx_event_handler, hwc,
				 mana_hwc_tx_event_handler, hwc, &hwc->cq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC CQ: %d\n", err);
		goto out;
	}

	err = mana_hwc_create_wq(hwc, GDMA_RQ, q_depth, max_req_msg_size,
				 hwc->cq, &hwc->rxq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC RQ: %d\n", err);
		goto out;
	}

	err = mana_hwc_create_wq(hwc, GDMA_SQ, q_depth, max_resp_msg_size,
				 hwc->cq, &hwc->txq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC SQ: %d\n", err);
		goto out;
	}

	hwc->num_inflight_msg = q_depth;
	hwc->max_req_msg_size = max_req_msg_size;
	hwc->max_resp_msg_size = max_resp_msg_size;

	return 0;
out:
	/* The setup path tears down any partially initialized queues. */
	return err;
}

static void mana_hwc_clear_cq_table(struct gdma_context *gc)
{
	struct gdma_queue **cq_table;

	cq_table = READ_ONCE(gc->cq_table);
	WRITE_ONCE(gc->max_num_cqs, 0);
	/* Stop new table readers before waiting for prior RCU readers. */
	smp_store_release(&gc->cq_table, NULL);
	synchronize_rcu();
	vfree(cq_table);
}

/* Setup is private; runtime teardown has unpublished and drained senders. */
static void mana_hwc_destroy_queues(struct hw_channel_context *hwc)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;

	mana_hwc_clear_cq_table(gc);

	if (hwc->cq) {
		mana_hwc_destroy_cq(gc, hwc->cq);
		hwc->cq = NULL;
	}

	if (hwc->txq) {
		mana_hwc_destroy_wq(hwc, hwc->txq);
		hwc->txq = NULL;
	}
	if (hwc->rxq) {
		mana_hwc_destroy_wq(hwc, hwc->rxq);
		hwc->rxq = NULL;
	}

	kfree(hwc->caller_ctx);
	hwc->caller_ctx = NULL;
	mana_gd_free_res_map(&hwc->inflight_msg_res);
	hwc->num_inflight_msg = 0;
}

static int mana_hwc_publish_channel(struct hw_channel_context *hwc)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&gc->hwc_lock, flags);
	if (WARN_ON_ONCE(gc->hwc.driver_data))
		err = -EBUSY;
	else
		gc->hwc.driver_data = hwc;
	spin_unlock_irqrestore(&gc->hwc_lock, flags);

	return err;
}

static struct hw_channel_context *
mana_hwc_unpublish_channel(struct gdma_context *gc)
{
	struct hw_channel_context *hwc;
	unsigned long flags;

	spin_lock_irqsave(&gc->hwc_lock, flags);
	hwc = gc->hwc.driver_data;
	gc->hwc.driver_data = NULL;
	spin_unlock_irqrestore(&gc->hwc_lock, flags);

	return hwc;
}

static void mana_hwc_retain_channel(struct hw_channel_context *hwc)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	unsigned long flags;

	spin_lock_irqsave(&gc->hwc_lock, flags);
	if (WARN_ON_ONCE(gc->hwc.driver_data))
		dev_err(hwc->dev, "HWC retention slot is already occupied\n");
	else
		gc->hwc.driver_data = hwc;
	spin_unlock_irqrestore(&gc->hwc_lock, flags);
}

static bool mana_hwc_senders_drained(struct gdma_context *gc,
				     struct hw_channel_context *hwc)
{
	unsigned long flags;
	bool drained;

	spin_lock_irqsave(&gc->hwc_lock, flags);
	drained = hwc->active_senders == 0;
	spin_unlock_irqrestore(&gc->hwc_lock, flags);

	return drained;
}

static void mana_hwc_stop_channel(struct hw_channel_context *hwc)
{
	struct gdma_resource *r = &hwc->inflight_msg_res;
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	unsigned long flags;
	int i;

	if (hwc->num_inflight_msg) {
		spin_lock_irqsave(&r->lock, flags);
		hwc->channel_up = false;
		spin_unlock_irqrestore(&r->lock, flags);
		/* Wake one admission waiter; each rejected waiter returns the
		 * permit and wakes the next.
		 */
		up(&hwc->sema);
	}
	mana_hwc_timeout_cancel(hwc);

	for (i = 0; hwc->caller_ctx && i < hwc->num_inflight_msg; i++) {
		struct hwc_caller_ctx *ctx;
		bool drop_resp_ref;

		spin_lock_irqsave(&r->lock, flags);
		if (!test_bit(i, r->map)) {
			spin_unlock_irqrestore(&r->lock, flags);
			continue;
		}

		ctx = &hwc->caller_ctx[i];
		spin_lock(&ctx->lock);
		spin_unlock(&r->lock);

		if (!ctx->responded)
			ctx->error = -ENODEV;
		ctx->output_buf = NULL;
		drop_resp_ref = mana_hwc_clear_resp_pending(hwc, ctx);
		ctx->responded = true;
		complete(&ctx->comp_event);
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (drop_resp_ref)
			hwc_ctx_put(hwc, ctx);
	}

	wait_event(gc->hwc_drain_waitq, mana_hwc_senders_drained(gc, hwc));
}

static void mana_hwc_fence_channel(struct gdma_context *gc,
				   struct hw_channel_context *hwc)
{
	if (!hwc->cq)
		return;

	if (hwc->cq->gdma_eq)
		mana_gd_fence_eq(gc, hwc->cq->gdma_eq);

	if (hwc->cq->gdma_cq)
		mana_hwc_unpublish_cq(gc, hwc->cq->gdma_cq);
}

static int mana_hwc_teardown_queues(struct hw_channel_context *hwc)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	int err;

	err = mana_smc_teardown_hwc(&gc->shm_channel, false,
				    &hwc->setup_active);
	if (err) {
		dev_err(hwc->dev,
			"HWC teardown failed: %d, retaining PF-visible resources\n",
			err);
		mana_hwc_fence_channel(gc, hwc);
		return err;
	}

	mana_hwc_destroy_queues(hwc);

	return 0;
}

static bool mana_hwc_release_channel(struct hw_channel_context *hwc)
{
	struct gdma_context *gc = hwc->gdma_dev->gdma_context;
	int err;

	mana_hwc_stop_channel(hwc);

	err = mana_hwc_teardown_queues(hwc);
	if (err) {
		mana_hwc_retain_channel(hwc);
		return false;
	}

	hwc->gdma_dev->doorbell = INVALID_DOORBELL;
	hwc->gdma_dev->pdid = INVALID_PDID;

	kfree(hwc);
	gc->hwc.gdma_context = NULL;

	return true;
}

static void mana_hwc_free_retained_wq(struct hwc_wq *wq)
{
	if (!wq)
		return;

	kfree(wq->msg_buf);
	kfree(wq->gdma_wq);
	kfree(wq);
}

/* Final disposal after IRQ and service-work teardown, not a retry path.
 * Free only software state: unacknowledged HWC DMA allocations stay live.
 */
void mana_hwc_free_retained_channel(struct gdma_context *gc)
{
	struct hw_channel_context *hwc = mana_hwc_unpublish_channel(gc);

	if (!hwc)
		return;

	mana_hwc_stop_channel(hwc);
	mana_hwc_clear_cq_table(gc);

	if (hwc->cq) {
		kfree(hwc->cq->gdma_eq);
		kfree(hwc->cq->gdma_cq);
		kfree(hwc->cq->comp_buf);
		kfree(hwc->cq);
	}

	mana_hwc_free_retained_wq(hwc->txq);
	mana_hwc_free_retained_wq(hwc->rxq);
	kfree(hwc->caller_ctx);
	mana_gd_free_res_map(&hwc->inflight_msg_res);
	kfree(hwc);
	gc->hwc.gdma_context = NULL;
}

static int
mana_hwc_validate_report(struct hw_channel_context *hwc,
			 const struct mana_hwc_init_report *report,
			 u32 expected_depth, bool check_depth,
			 bool require_exact_msg_sizes)
{
	if (!report->queue_depth || !report->max_req_msg_size ||
	    !report->max_resp_msg_size) {
		dev_err(hwc->dev,
			"HWC: invalid maxima depth=%u req=%u resp=%u\n",
			report->queue_depth, report->max_req_msg_size,
			report->max_resp_msg_size);
		return -EPROTO;
	}

	if (require_exact_msg_sizes &&
	    (report->max_req_msg_size != HW_CHANNEL_MAX_REQUEST_SIZE ||
	     report->max_resp_msg_size != HW_CHANNEL_MAX_RESPONSE_SIZE)) {
		dev_err(hwc->dev,
			"HWC: rebuilt message maxima req=%u resp=%u, expected %u/%u\n",
			report->max_req_msg_size, report->max_resp_msg_size,
			HW_CHANNEL_MAX_REQUEST_SIZE,
			HW_CHANNEL_MAX_RESPONSE_SIZE);
		return -EPROTO;
	}

	if (check_depth && report->queue_depth != expected_depth) {
		dev_err(hwc->dev, "HWC: rebuilt depth %u, expected %u\n",
			report->queue_depth, expected_depth);
		return -EPROTO;
	}

	return 0;
}

static int mana_hwc_finish_channel(struct hw_channel_context *hwc,
				   const struct mana_hwc_init_report *report)
{
	int err;

	/* MAX_REQUEST sizes the RQ; MAX_RESPONSE sizes the SQ. */
	hwc->rx_msg_size_limit = report->max_req_msg_size;
	hwc->tx_msg_size_limit = report->max_resp_msg_size;

	err = mana_hwc_test_channel(hwc);
	if (err)
		dev_err(hwc->dev, "Failed to test HWC: %d\n", err);

	return err;
}

static int mana_hwc_build_channel(struct hw_channel_context *hwc, u16 q_depth,
				  struct mana_hwc_init_report *report)
{
	int err;

	err = mana_hwc_init_queues(hwc, q_depth,
				   HW_CHANNEL_MAX_REQUEST_SIZE,
				   HW_CHANNEL_MAX_RESPONSE_SIZE);
	if (err) {
		dev_err(hwc->dev, "Failed to initialize HWC depth %u: %d\n",
			q_depth, err);
		return err;
	}

	err = mana_hwc_establish_channel(hwc, report);
	if (err)
		dev_err(hwc->dev, "Failed to establish HWC depth %u: %d\n",
			q_depth, err);

	return err;
}

static int
mana_hwc_restore_bootstrap(struct hw_channel_context *hwc,
			   struct mana_hwc_init_report *report)
{
	int err;

	err = mana_hwc_build_channel(hwc,
				     HW_CHANNEL_VF_BOOTSTRAP_QUEUE_DEPTH,
				     report);
	if (err)
		return err;

	err = mana_hwc_validate_report(hwc, report, 0, false, false);
	if (err)
		return err;

	return mana_hwc_finish_channel(hwc, report);
}

static int mana_hwc_rebuild_channel(struct hw_channel_context *hwc,
				    u16 q_depth,
				    struct mana_hwc_init_report *report)
{
	u32 timeout_ms = mana_hwc_timeout_read(hwc);
	int cleanup_err;
	int err;

	err = mana_hwc_teardown_queues(hwc);
	if (err)
		return err;

	err = mana_hwc_build_channel(hwc, q_depth, report);
	if (!err)
		err = mana_hwc_validate_report(hwc, report, q_depth, true, true);
	if (!err)
		err = mana_hwc_finish_channel(hwc, report);
	if (!err)
		return 0;

	dev_warn(hwc->dev,
		 "HWC depth %u rebuild failed, restoring bootstrap: %d\n",
		 q_depth, err);

	cleanup_err = mana_hwc_teardown_queues(hwc);
	if (cleanup_err)
		return cleanup_err;

	/* Do not carry the failed test's reduced wait into the retry. */
	mana_hwc_timeout_update(hwc, timeout_ms);

	return mana_hwc_restore_bootstrap(hwc, report);
}

static int mana_hwc_prepare_channel(struct hw_channel_context *hwc)
{
	struct mana_hwc_init_report report;
	u16 rebuild_depth;
	int err;

	err = mana_hwc_build_channel(hwc,
				     HW_CHANNEL_VF_BOOTSTRAP_QUEUE_DEPTH,
				     &report);
	if (err)
		return err;

	err = mana_hwc_validate_report(hwc, &report, 0, false, false);
	if (err)
		return err;

	if (report.queue_depth > HW_CHANNEL_MAX_QUEUE_DEPTH) {
		dev_warn(hwc->dev,
			 "HWC depth %u exceeds limit %u, keeping bootstrap\n",
			 report.queue_depth, HW_CHANNEL_MAX_QUEUE_DEPTH);
	} else if (report.queue_depth >
		   HW_CHANNEL_VF_BOOTSTRAP_QUEUE_DEPTH &&
		   (report.max_req_msg_size != HW_CHANNEL_MAX_REQUEST_SIZE ||
		    report.max_resp_msg_size != HW_CHANNEL_MAX_RESPONSE_SIZE)) {
		dev_warn(hwc->dev,
			 "HWC maxima req=%u resp=%u differ from rebuild policy %u/%u, keeping bootstrap\n",
			 report.max_req_msg_size, report.max_resp_msg_size,
			 HW_CHANNEL_MAX_REQUEST_SIZE,
			 HW_CHANNEL_MAX_RESPONSE_SIZE);
	} else if (report.queue_depth >
		   HW_CHANNEL_VF_BOOTSTRAP_QUEUE_DEPTH) {
		rebuild_depth = report.queue_depth;
		return mana_hwc_rebuild_channel(hwc, rebuild_depth, &report);
	}

	return mana_hwc_finish_channel(hwc, &report);
}

int mana_hwc_create_channel(struct gdma_context *gc)
{
	struct gdma_dev *gd = &gc->hwc;
	struct hw_channel_context *hwc;
	int err;

	/* Retry a retained context before assigning queues to the PF again. */
	if (gd->driver_data) {
		mana_hwc_destroy_channel(gc);
		if (gd->driver_data)
			return -ETIMEDOUT;
	}

	hwc = kzalloc_obj(*hwc);
	if (!hwc)
		return -ENOMEM;

	gd->gdma_context = gc;
	hwc->gdma_dev = gd;
	hwc->dev = gc->dev;
	WRITE_ONCE(hwc->hwc_timeout, HW_CHANNEL_WAIT_RESOURCE_TIMEOUT_MS);
	init_waitqueue_head(&gc->hwc_drain_waitq);

	/* HWC's instance number is always 0. */
	gd->dev_id.as_uint32 = 0;
	gd->dev_id.type = GDMA_DEVICE_HWC;

	gd->pdid = INVALID_PDID;
	gd->doorbell = INVALID_DOORBELL;

	err = mana_hwc_prepare_channel(hwc);
	if (err) {
		mana_hwc_release_channel(hwc);
		return err;
	}

	err = mana_hwc_publish_channel(hwc);
	if (err) {
		mana_hwc_release_channel(hwc);
		return err;
	}

	return 0;
}

void mana_hwc_destroy_channel(struct gdma_context *gc)
{
	struct hw_channel_context *hwc;

	hwc = mana_hwc_unpublish_channel(gc);
	if (!hwc)
		return;

	mana_hwc_release_channel(hwc);
}

static void mana_hwc_abort_request(struct hw_channel_context *hwc,
				   struct hwc_caller_ctx *ctx)
{
	unsigned long flags;
	bool drop_resp_ref;

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->output_buf = NULL;
	drop_resp_ref = mana_hwc_clear_resp_pending(hwc, ctx);
	ctx->responded = true;
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (drop_resp_ref)
		hwc_ctx_put(hwc, ctx);
	hwc_ctx_put(hwc, ctx);
}

static int mana_hwc_submit_request(struct hw_channel_context *hwc,
				   struct hwc_caller_ctx *ctx,
				   struct hwc_work_request *tx_wr)
{
	unsigned long flags;
	bool drop_resp_ref = false;
	int err;

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->responded) {
		err = ctx->error ?: -ENODEV;
	} else {
		err = mana_hwc_post_tx_wqe(hwc->txq, tx_wr,
					   hwc->dest_vrq_id,
					   hwc->dest_vrcq_id, false);
		if (err) {
			ctx->output_buf = NULL;
			drop_resp_ref = mana_hwc_clear_resp_pending(hwc, ctx);
			ctx->responded = true;
		}
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!err)
		return 0;

	if (drop_resp_ref)
		hwc_ctx_put(hwc, ctx);
	hwc_ctx_put(hwc, ctx);

	return err;
}

static int mana_hwc_response_result(struct hw_channel_context *hwc,
				    u32 command, int err, u32 status)
{
	if (err)
		return err;

	if (!status || status == GDMA_STATUS_MORE_ENTRIES)
		return 0;

	if (status == GDMA_STATUS_CMD_UNSUPPORTED)
		return -EOPNOTSUPP;

	if (command != MANA_QUERY_PHY_STAT)
		dev_err(hwc->dev, "Command 0x%x failed with status: 0x%x\n",
			command, status);

	return -EPROTO;
}

static int mana_hwc_wait_for_response(struct hw_channel_context *hwc,
				      struct hwc_caller_ctx *ctx,
				      u32 command)
{
	unsigned long flags;
	bool abandoned = false;
	u32 wait_ms;
	u32 status;
	int err;

	wait_ms = mana_hwc_timeout_read(hwc);
	if (wait_for_completion_timeout(&ctx->comp_event,
					msecs_to_jiffies(wait_ms))) {
		spin_lock_irqsave(&ctx->lock, flags);
		ctx->output_buf = NULL;
		err = ctx->error;
		status = ctx->status_code;
		spin_unlock_irqrestore(&ctx->lock, flags);
		hwc_ctx_put(hwc, ctx);

		return mana_hwc_response_result(hwc, command, err, status);
	}

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->output_buf = NULL;
	err = ctx->error;
	status = ctx->status_code;
	if (err == -EINPROGRESS) {
		ctx->error = -ETIMEDOUT;
		ctx->responded = true;
		atomic_inc(&hwc->abandoned_msgs);
		abandoned = true;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!abandoned) {
		hwc_ctx_put(hwc, ctx);
		return mana_hwc_response_result(hwc, command, err, status);
	}

	if (wait_ms)
		dev_err(hwc->dev, "Command 0x%x timed out: %u ms\n",
			command, wait_ms);

	mana_hwc_timeout_reduce(hwc);
	hwc_ctx_put(hwc, ctx);

	return -ETIMEDOUT;
}

int mana_hwc_send_request(struct hw_channel_context *hwc, u32 req_len,
			  const void *req, u32 resp_len, void *resp)
{
	struct hwc_work_request *tx_wr;
	struct gdma_req_hdr *req_msg;
	struct hwc_caller_ctx *ctx;
	u32 command;
	int err;

	err = mana_hwc_get_msg_index(hwc, req_len, resp, resp_len, &ctx);
	if (err)
		return err;

	tx_wr = &hwc->txq->msg_buf->reqs[ctx->msg_id];
	if (req_len > tx_wr->buf_len) {
		dev_err(hwc->dev, "HWC: req msg size: %d > %d\n", req_len,
			tx_wr->buf_len);
		mana_hwc_abort_request(hwc, ctx);
		return -EINVAL;
	}

	req_msg = tx_wr->buf_va;
	if (req)
		memcpy(req_msg, req, req_len);
	req_msg->req.hwc_msg_id = ctx->msg_id;

	tx_wr->msg_size = req_len;
	command = req_msg->req.msg_type;

	err = mana_hwc_submit_request(hwc, ctx, tx_wr);
	if (err)
		return err;

	return mana_hwc_wait_for_response(hwc, ctx, command);
}
