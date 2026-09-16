// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/bits.h>
#include <linux/dma-mapping.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include "nbl_channel.h"

static int nbl_chan_add_msg_handler(struct nbl_channel_mgt *chan_mgt,
				    u16 msg_type, nbl_chan_resp func,
				    void *priv)
{
	struct nbl_chan_msg_node_data handler = { 0 };
	int ret;

	handler.func = func;
	handler.priv = priv;
	ret = nbl_common_alloc_hash_node(chan_mgt->handle_hash_tbl, &msg_type,
					 &handler, NULL);

	return ret;
}

static int nbl_chan_init_msg_handler(struct nbl_channel_mgt *chan_mgt)
{
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_hash_tbl_key tbl_key = { 0 };

	tbl_key.dev = common->dev;
	tbl_key.key_size = sizeof(u16);
	tbl_key.data_size = sizeof(struct nbl_chan_msg_node_data);
	tbl_key.bucket_size = NBL_CHAN_HANDLER_TBL_BUCKET_SIZE;

	chan_mgt->handle_hash_tbl = nbl_common_init_hash_table(&tbl_key);
	if (!chan_mgt->handle_hash_tbl)
		return -ENOMEM;

	return 0;
}

static void nbl_chan_remove_msg_handler(struct nbl_channel_mgt *chan_mgt)
{
	if (!chan_mgt->handle_hash_tbl)
		return;
	nbl_common_remove_hash_table(chan_mgt->handle_hash_tbl);
	chan_mgt->handle_hash_tbl = NULL;
}

static void nbl_chan_init_queue_param(struct nbl_chan_info *chan_info,
				      u16 num_txq_entries, u16 num_rxq_entries,
				      u16 txq_buf_size, u16 rxq_buf_size)
{
	chan_info->num_txq_entries = num_txq_entries;
	chan_info->num_rxq_entries = num_rxq_entries;
	chan_info->txq_buf_size = txq_buf_size;
	chan_info->rxq_buf_size = rxq_buf_size;
	atomic_set(&chan_info->inflight_tx_cnt, 0);
	WRITE_ONCE(chan_info->shutdn, false);
	WRITE_ONCE(chan_info->active, false);
	WRITE_ONCE(chan_info->wait_head_index, 0);
	memset(chan_info->state, 0, sizeof(chan_info->state));
	init_waitqueue_head(&chan_info->inflight_wait);
}

static int nbl_chan_init_tx_queue(struct nbl_common_info *common,
				  struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct device *dev = common->dev;
	size_t size =
		chan_info->num_txq_entries * sizeof(struct nbl_chan_tx_desc);
	u16 i;

	txq->desc.tx_desc =
		dmam_alloc_coherent(dev, size, &txq->dma, GFP_KERNEL);
	if (!txq->desc.tx_desc)
		return -ENOMEM;

	chan_info->wait = devm_kcalloc(dev, chan_info->num_txq_entries,
				       sizeof(*chan_info->wait), GFP_KERNEL);
	if (!chan_info->wait)
		return -ENOMEM;
	for (i = 0; i < chan_info->num_txq_entries; i++) {
		init_waitqueue_head(&chan_info->wait[i].wait_queue);
		WRITE_ONCE(chan_info->wait[i].status, NBL_MBX_STATUS_IDLE);
		WRITE_ONCE(chan_info->wait[i].acked, 0);
		WRITE_ONCE(chan_info->wait[i].ack_data, NULL);
		WRITE_ONCE(chan_info->wait[i].ack_data_len, 0);
		WRITE_ONCE(chan_info->wait[i].ack_err, 0);
		WRITE_ONCE(chan_info->wait[i].msg_type, 0);
		WRITE_ONCE(chan_info->wait[i].msg_index, 0);
		WRITE_ONCE(chan_info->wait[i].dstid, 0);
	}

	txq->buf = devm_kcalloc(dev, chan_info->num_txq_entries,
				sizeof(*txq->buf), GFP_KERNEL);
	if (!txq->buf)
		return -ENOMEM;

	return 0;
}

static int nbl_chan_init_rx_queue(struct nbl_common_info *common,
				  struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct device *dev = common->dev;
	size_t size =
		chan_info->num_rxq_entries * sizeof(struct nbl_chan_rx_desc);

	rxq->desc.rx_desc =
		dmam_alloc_coherent(dev, size, &rxq->dma, GFP_KERNEL);
	if (!rxq->desc.rx_desc) {
		dev_err_ratelimited(dev,
				    "Allocate DMA for chan rx descriptor ring failed\n");
		return -ENOMEM;
	}

	rxq->buf = devm_kcalloc(dev, chan_info->num_rxq_entries,
				sizeof(*rxq->buf), GFP_KERNEL);
	if (!rxq->buf)
		return -ENOMEM;

	return 0;
}

static int nbl_chan_init_queue(struct nbl_common_info *common,
			       struct nbl_chan_info *chan_info)
{
	int err;

	err = nbl_chan_init_tx_queue(common, chan_info);
	if (err)
		return err;

	err = nbl_chan_init_rx_queue(common, chan_info);

	return err;
}

static void nbl_chan_config_queue(struct nbl_channel_mgt *chan_mgt,
				  struct nbl_chan_info *chan_info, bool tx)
{
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;
	struct nbl_hw_mgt *p = chan_mgt->hw_ops_tbl->priv;
	struct nbl_chan_ring *ring;
	dma_addr_t addr;
	int size_bwid;

	if (tx)
		ring = &chan_info->txq;
	else
		ring = &chan_info->rxq;
	addr = ring->dma;
	if (tx) {
		size_bwid = ilog2(chan_info->num_txq_entries);
		hw_ops->config_mailbox_txq(p, addr, size_bwid);
	} else {
		size_bwid = ilog2(chan_info->num_rxq_entries);
		hw_ops->config_mailbox_rxq(p, addr, size_bwid);
	}
}

static int nbl_chan_alloc_all_tx_bufs(struct nbl_channel_mgt *chan_mgt,
				      struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct device *dev = chan_mgt->common->dev;
	struct nbl_chan_buf *buf;
	u16 i;

	for (i = 0; i < chan_info->num_txq_entries; i++) {
		buf = &txq->buf[i];
		buf->va = dmam_alloc_coherent(dev, chan_info->txq_buf_size,
					      &buf->pa, GFP_KERNEL);
		if (!buf->va) {
			dev_err_ratelimited(dev,
					    "Allocate buffer for chan tx queue failed\n");
			return -ENOMEM;
		}
	}

	txq->next_to_clean = 0;
	txq->next_to_use = 0;
	txq->tail_ptr = 0;

	return 0;
}

static void nbl_chan_cfg_qinfo_map_table(struct nbl_channel_mgt *chan_mgt,
					 u8 bus, u8 devid)
{
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;
	struct nbl_hw_mgt *p = chan_mgt->hw_ops_tbl->priv;
	u32 pf_mask = 0;
	u8 func_id;

	/*
	 * k_pf_mask rule: bit N == 0 means PF#N enabled, bit N == 1 masked out.
	 * Program mailbox QINFO entry for each hardware-active PF func_id.
	 *
	 * Note: This loop iterates over raw hardware PF func_id.
	 * Upper resource initialization nbl_res_init_pf_num() enforces
	 * product constraints: only 1/2/4 contiguous PFs(PF0 / PF0~1 / PF0~3)
	 * are allowed. Non-contiguous or unsupported PF count will be rejected
	 * before reaching this function.
	 */
	hw_ops->get_host_pf_mask(p, &pf_mask);
	for (func_id = 0; func_id < NBL_MAX_PF; func_id++) {
		if (!(pf_mask & (1 << func_id)))
			hw_ops->cfg_mailbox_qinfo(p, func_id, bus,
						  devid, func_id);
	}
}

static int nbl_chan_alloc_all_rx_bufs(struct nbl_channel_mgt *chan_mgt,
				      struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct device *dev = chan_mgt->common->dev;
	struct nbl_chan_rx_desc *desc;
	struct nbl_chan_buf *buf;
	u16 i;

	for (i = 0; i < chan_info->num_rxq_entries; i++) {
		buf = &rxq->buf[i];
		buf->va = dmam_alloc_coherent(dev, chan_info->rxq_buf_size,
					      &buf->pa, GFP_KERNEL);
		if (!buf->va) {
			dev_err_ratelimited(dev,
					    "Allocate buffer for chan rx queue failed\n");
			goto err;
		}
	}

	desc = rxq->desc.rx_desc;
	/*
	 * Initially leave one RX descriptor unused so that
	 * next_to_clean and next_to_use can distinguish an empty
	 * ring from a full ring.
	 *
	 * The unused slot is replenished as RX descriptors are
	 * consumed and recycled.
	 */
	for (i = 0; i < chan_info->num_rxq_entries - 1; i++) {
		buf = &rxq->buf[i];
		desc[i].buf_addr = cpu_to_le64(buf->pa);
		desc[i].buf_len = cpu_to_le32(chan_info->rxq_buf_size);
		desc[i].flags = cpu_to_le16(BIT(NBL_CHAN_RX_DESC_AVAIL));
	}

	rxq->next_to_clean = 0;
	rxq->next_to_use = chan_info->num_rxq_entries - 1;
	rxq->tail_ptr = chan_info->num_rxq_entries - 1;

	return 0;
err:
	return -ENOMEM;
}

static int nbl_chan_alloc_all_bufs(struct nbl_channel_mgt *chan_mgt,
				   struct nbl_chan_info *chan_info)
{
	int err;

	err = nbl_chan_alloc_all_tx_bufs(chan_mgt, chan_info);
	if (err)
		return err;
	err = nbl_chan_alloc_all_rx_bufs(chan_mgt, chan_info);

	return err;
}

static void nbl_chan_stop_queue(struct nbl_channel_mgt *chan_mgt)
{
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;

	hw_ops->stop_mailbox_rxq(chan_mgt->hw_ops_tbl->priv);
	hw_ops->stop_mailbox_txq(chan_mgt->hw_ops_tbl->priv);
}

static int nbl_chan_teardown_queue(struct nbl_channel_mgt *chan_mgt,
				   u8 chan_type)
{
	struct nbl_chan_info *chan_info = chan_mgt->chan_info[chan_type];
	struct nbl_chan_waitqueue_head *wait_head;
	struct work_struct *task;
	int ret = 0;
	u16 i;

	if (!READ_ONCE(chan_info->active)) {
		dev_warn(chan_mgt->common->dev, "channel not active, skip duplicate teardown\n");
		return 0;
	}
	/*
	 * Step1:
	 * block new sender
	 */
	mutex_lock(&chan_info->state_lock);
	WRITE_ONCE(chan_info->shutdn, true);
	task = READ_ONCE(chan_info->clean_task);
	WRITE_ONCE(chan_info->clean_task, NULL);
	mutex_unlock(&chan_info->state_lock);
	/*
	 * Step2:
	 * abort pending ACK waiters
	 */

	mutex_lock(&chan_info->pending_lock);
	for (i = 0; i < chan_info->num_txq_entries; i++) {
		wait_head = &chan_info->wait[i];
		/* Only wake threads that are actually waiting */
		if (READ_ONCE(wait_head->status) == NBL_MBX_STATUS_WAITING) {
			/* Update all status fields first */
			WRITE_ONCE(wait_head->status, NBL_MBX_STATUS_TIMEOUT);
			WRITE_ONCE(wait_head->ack_err, (s32)-EIO);
			/* Ensure status visible before acked flag */
			smp_wmb();
			WRITE_ONCE(wait_head->acked, 1);
			wake_up(&wait_head->wait_queue);
		}
	}
	mutex_unlock(&chan_info->pending_lock);
	/*
	 * Step3:
	 * wait all sender exit
	 *
	 * Drain strategy mirrors mlx5 command interface teardown:
	 * set shutdown flag first, abort all pending waiters, then
	 * block until inflight_tx_cnt reaches zero.
	 *
	 * A timeout here is treated as an exceptional condition rather
	 * than a fatal error, following the same rationale as mlx5:
	 *   - shutdn is already set, so every sender path observes it
	 *     at its next checkpoint and exits;
	 *   - interrupt-driven senders have a 3s ACK wait
	 *     (NBL_CHAN_ACK_WAIT_TIME); polling senders re-check shutdn
	 *     on every 1-1.2ms iteration, so both exit promptly after
	 *     shutdown is signaled rather than running to full timeout;
	 *   - timeout is treated as an exceptional condition; callers
	 *     must not access queue resources while an inflight sender
	 *     may still be active;
	 *   - in that hardware-dead case proceeding with teardown cannot
	 *     make the situation worse, and avoids hanging rmmod forever.
	 */
	ret = wait_event_timeout(chan_info->inflight_wait,
				 atomic_read(&chan_info->inflight_tx_cnt) == 0,
				 msecs_to_jiffies(5000));

	if (!ret) {
		dev_warn(chan_mgt->common->dev,
			 "teardown: inflight tx drain timeout\n");
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}

	/* After all TX drained, stop hardware queue */
	nbl_chan_stop_queue(chan_mgt);

	/* All send paths drained, safely cancel cleanup work */
	if (task)
		cancel_work_sync(task);
	WRITE_ONCE(chan_info->active, false);
	return ret;
}

static int nbl_chan_setup_queue(struct nbl_channel_mgt *chan_mgt, u8 chan_type)
{
	struct nbl_chan_info *chan_info = chan_mgt->chan_info[chan_type];
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	int err;

	if (READ_ONCE(chan_info->active)) {
		dev_warn(common->dev, "channel already active, reject duplicate setup\n");
		return -EBUSY;
	}
	nbl_chan_init_queue_param(chan_info, NBL_CHAN_QUEUE_LEN,
				  NBL_CHAN_QUEUE_LEN, NBL_CHAN_BUF_LEN,
				  NBL_CHAN_BUF_LEN);
	err = nbl_chan_init_queue(common, chan_info);
	if (err)
		return err;
	err = nbl_chan_alloc_all_bufs(chan_mgt, chan_info);
	if (err)
		return err;
	nbl_chan_config_queue(chan_mgt, chan_info, true); /* tx */
	nbl_chan_config_queue(chan_mgt, chan_info, false); /* rx */
	nbl_chan_update_tail_ptr(hw_ops, chan_mgt->hw_ops_tbl->priv,
				 rxq->tail_ptr, NBL_MB_RX_QID);
	WRITE_ONCE(chan_info->active, true);
	return 0;
}

static bool nbl_chan_txq_full(struct nbl_chan_ring *txq,
			      u16 num_entries)
{
	return NBL_NEXT_ID(txq->next_to_use, num_entries - 1) ==
	       txq->next_to_clean;
}

static int nbl_chan_update_txqueue(struct nbl_channel_mgt *chan_mgt,
				   struct nbl_chan_info *chan_info,
				   struct nbl_chan_tx_param *param)
{
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_buf *tx_buf;

	if (nbl_chan_txq_full(txq, chan_info->num_txq_entries))
		return -EBUSY;
	if (param->arg_len > NBL_CHAN_BUF_LEN - sizeof(*tx_desc))
		return -EINVAL;
	tx_desc =
		NBL_CHAN_TX_RING_TO_DESC(txq, txq->next_to_use);
	tx_buf =
		NBL_CHAN_TX_RING_TO_BUF(txq, txq->next_to_use);
	tx_desc->dstid = cpu_to_le16(param->dstid);
	tx_desc->msg_type = cpu_to_le16(param->msg_type);
	tx_desc->msgid = cpu_to_le16(param->msgid);

	/*
	 * srcid field is filled by mailbox hardware after peer receives this
	 * packet, driver producer never writes srcid; reused descriptor slots
	 * will contain stale srcid value temporarily until hardware overwrites
	 * it.
	 */
	if (param->arg_len > NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN) {
		if (param->arg)
			memcpy(tx_buf->va, param->arg, param->arg_len);
		tx_desc->buf_addr = cpu_to_le64(tx_buf->pa);
		tx_desc->buf_len = cpu_to_le16(param->arg_len);
		tx_desc->data_len = 0;
		memset(tx_desc->data, 0, sizeof(tx_desc->data));
	} else {
		memset(tx_desc->data, 0, sizeof(tx_desc->data));
		memset(&tx_desc->buf_addr, 0, sizeof(tx_desc->buf_addr));
		if (param->arg && param->arg_len > 0)
			memcpy(tx_desc->data, param->arg, param->arg_len);
		tx_desc->buf_len = 0;
		tx_desc->data_len = cpu_to_le16(param->arg_len);
	}
	/* Ensure descriptor data visible to device before AVAIL flag */
	dma_wmb();
	tx_desc->flags = cpu_to_le16(BIT(NBL_CHAN_TX_DESC_AVAIL));

	txq->next_to_use =
		NBL_NEXT_ID(txq->next_to_use, chan_info->num_txq_entries - 1);
	txq->tail_ptr++;

	return 0;
}

/*
 * Quiesce the TX mailbox queue and reclaim all outstanding
 * descriptors.  Called from the timeout path of nbl_chan_kick_tx_ring()
 * with txq_lock held.
 *
 * The device failed to fetch/complete the current descriptor within the
 * polling window.  We assert QUEUE_RST to stop further DMA fetches,
 * reclaim every descriptor between next_to_clean and next_to_use,
 * reset the software tail_ptr counter to match the hardware reset state,
 * and re-enable the queue so subsequent sends can proceed.
 */
static void nbl_chan_quiesce_and_reclaim_tx(struct nbl_channel_mgt *chan_mgt,
					    struct nbl_chan_info *chan_info)
{
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;
	struct nbl_hw_mgt *hw_priv = chan_mgt->hw_ops_tbl->priv;
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct nbl_chan_tx_desc *tx_desc;

	/* Assert QUEUE_RST to stop hardware fetching new descriptors */
	hw_ops->stop_mailbox_txq(hw_priv);
	hw_ops->flush_write(hw_priv);

	/*
	 * Reclaim all outstanding descriptors between next_to_clean and
	 * next_to_use.  Under txq_lock there is at most one in-flight
	 * descriptor, but iterate the full range for robustness.
	 */
	while (txq->next_to_clean != txq->next_to_use) {
		tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq,
						   txq->next_to_clean);
		WRITE_ONCE(tx_desc->flags, 0);
		txq->next_to_clean =
			NBL_NEXT_ID(txq->next_to_clean,
				    chan_info->num_txq_entries - 1);
	}

	/*
	 * Hardware tail_ptr counter is cleared by QUEUE_RST.  Reset
	 * software counter to match so the next doorbell update does
	 * not produce a false 16-bit wrap delta.
	 */
	txq->tail_ptr = 0;
	txq->next_to_use = 0;
	txq->next_to_clean = 0;

	/* Re-enable queue with current ring base and size */
	nbl_chan_config_queue(chan_mgt, chan_info, true);
}

static int nbl_chan_kick_tx_ring(struct nbl_channel_mgt *chan_mgt,
				 struct nbl_chan_info *chan_info)
{
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct device *dev = chan_mgt->common->dev;
	int max_retries = NBL_CHAN_TX_WAIT_TIMES;
	struct nbl_chan_tx_desc *tx_desc;
	int retry_count = 0;
	u16 msg_type;

	nbl_chan_update_tail_ptr(hw_ops, chan_mgt->hw_ops_tbl->priv,
				 txq->tail_ptr, NBL_MB_TX_QID);

	tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq, txq->next_to_clean);
	/*
	 * Poll for HW to mark descriptor as USED.
	 * Mailbox is a low-speed control channel for management commands.
	 * We avoid enabling dedicated per-TX interrupt for single control
	 * message to reduce interrupt overhead, so use bounded polling
	 * with small delay instead.
	 */
	while (retry_count < max_retries) {
		if (READ_ONCE(chan_info->shutdn))
			return -ESHUTDOWN;

		if (le16_to_cpu(READ_ONCE(tx_desc->flags)) &
		    BIT(NBL_CHAN_TX_DESC_USED)) {
			 /*
			  * Order reads of other device-written descriptor
			  * fields after observing USED.  Matches the RX side
			  * pattern in nbl_chan_clean_queue().
			  */
			dma_rmb();
			break;
		}

		retry_count++;
		if (retry_count == max_retries) {
			msg_type = le16_to_cpu(READ_ONCE(tx_desc->msg_type));
			dev_err_ratelimited(dev, "chan send msg type: %d timeout\n",
					    msg_type);
			/*
			 * Device failed to complete this descriptor.
			 * Quiesce the queue, reclaim the timed-out
			 * descriptor, and re-enable so future sends can
			 * proceed instead of stalling the ring full.
			 */
			nbl_chan_quiesce_and_reclaim_tx(chan_mgt,
							chan_info);
			return -ETIMEDOUT;
		}
		usleep_range(NBL_CHAN_TX_WAIT_US, NBL_CHAN_TX_WAIT_US_MAX);
	}

	txq->next_to_clean = txq->next_to_use;

	return 0;
}

static void nbl_chan_recv_ack_msg(void *priv, u16 srcid, u16 msgid, void *data,
				  u32 data_len)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_waitqueue_head *wait_head = NULL;
	struct device *dev = chan_mgt->common->dev;
	struct nbl_chan_info *chan_info =
		chan_mgt->chan_info[NBL_CHAN_TYPE_MAILBOX];
	u16 w_dstid, w_msgtype, w_msgidx;
	u32 *payload = data;
	u16 ack_msgtype = 0;
	u16 ack_msgid = 0;
	u32 ack_datalen;
	void *ack_data;
	u32 copy_len;
	int w_status;
	s32 raw_err;

	if (READ_ONCE(chan_info->shutdn))
		return;
	if (data_len > NBL_CHAN_BUF_LEN ||
	    data_len < NBL_CHAN_ACK_HEAD_LEN * sizeof(u32)) {
		dev_err_ratelimited(dev, "Invalid ACK data_len: %u\n",
				    data_len);
		return;
	}
	ack_datalen = data_len - NBL_CHAN_ACK_HEAD_LEN * sizeof(u32);
	ack_msgtype = le16_to_cpu(*(__le16 *)(payload + NBL_CHAN_MSG_TYPE_POS));
	ack_msgid = le16_to_cpu(*(__le16 *)(payload + NBL_CHAN_MSG_ID_POS));
	if (FIELD_GET(NBL_CHAN_MSGID_LOC_MASK, ack_msgid) >=
	    chan_info->num_txq_entries) {
		dev_err_ratelimited(dev, "chan recv msg id: %u err\n",
				    ack_msgid);
		return;
	}
	wait_head =
		&chan_info->wait[FIELD_GET(NBL_CHAN_MSGID_LOC_MASK, ack_msgid)];

	mutex_lock(&chan_info->pending_lock);

	/* Cache repeated READ_ONCE values */
	w_dstid = READ_ONCE(wait_head->dstid);
	w_status = READ_ONCE(wait_head->status);
	w_msgtype = READ_ONCE(wait_head->msg_type);
	w_msgidx = READ_ONCE(wait_head->msg_index);

	if (srcid != w_dstid) {
		mutex_unlock(&chan_info->pending_lock);
		dev_err_ratelimited(dev, "ACK srcid=%u != dstid=%u, rejecting\n",
				    srcid, w_dstid);
		return;
	}
	if (w_status != NBL_MBX_STATUS_WAITING) {
		mutex_unlock(&chan_info->pending_lock);
		dev_err_ratelimited(dev,
				    "Skip ack invalid status, wait msgtype:%u idx:%u status:%d ack msgtype:%u msgid:%u datalen:%u\n",
				    w_msgtype, w_msgidx, w_status,
				    ack_msgtype, ack_msgid, ack_datalen);
		return;
	}

	if (w_msgtype != ack_msgtype) {
		mutex_unlock(&chan_info->pending_lock);
		dev_err_ratelimited(dev,
				    "Skip ack msgtype mismatch, wait msgtype:%u idx:%u ack msgtype:%u msgid:%u\n",
				    w_msgtype, w_msgidx, ack_msgtype,
				    ack_msgid);
		return;
	}
	if (FIELD_GET(NBL_CHAN_MSGID_INDEX_MASK, ack_msgid) != w_msgidx) {
		mutex_unlock(&chan_info->pending_lock);
		dev_err_ratelimited(dev,
				    "Stale ACK: expected index=%u, got msgid=%u\n",
				    w_msgidx, ack_msgid);
		return;
	}

	raw_err = (s32)le32_to_cpu(*(__le32 *)&payload[NBL_CHAN_ACK_RET_POS]);
	if (raw_err > 0 || raw_err < -MAX_ERRNO)
		raw_err = -EREMOTEIO;

	WRITE_ONCE(wait_head->ack_err, raw_err);

	copy_len = min_t(u32, READ_ONCE(wait_head->ack_data_len), ack_datalen);
	if (READ_ONCE(wait_head->ack_err) >= 0 && copy_len > 0) {
		ack_data = READ_ONCE(wait_head->ack_data);
		if (!ack_data) {
			dev_err_ratelimited(dev, "ACK payload dropped: ack_data is NULL\n");
			WRITE_ONCE(wait_head->ack_data_len, 0);
			goto ack_done;
		}
		memcpy((char *)ack_data,
		       payload + NBL_CHAN_ACK_HEAD_LEN, copy_len);
		WRITE_ONCE(wait_head->ack_data_len, (u16)copy_len);
	} else {
		WRITE_ONCE(wait_head->ack_data_len, 0);
	}
ack_done:
	/* Guarantee payload data finished before acked flag visible */
	smp_wmb();
	WRITE_ONCE(wait_head->acked, 1);
	WRITE_ONCE(wait_head->status, NBL_MBX_STATUS_ACKD);
	mutex_unlock(&chan_info->pending_lock);
	wake_up(&wait_head->wait_queue);
}

static void nbl_chan_recv_msg(struct nbl_channel_mgt *chan_mgt, void *data)
{
	struct device *dev = chan_mgt->common->dev;
	struct nbl_chan_msg_node_data *msg_handler;
	u16 msg_type, payload_len, srcid, msgid;
	struct nbl_chan_info *chan_info =
		chan_mgt->chan_info[NBL_CHAN_TYPE_MAILBOX];
	struct nbl_chan_tx_desc *tx_desc;
	void *payload;
	size_t avail_space;
	u16 data_len_fw;

	if (READ_ONCE(chan_info->shutdn))
		return;

	tx_desc = data;
	msg_type = le16_to_cpu(READ_ONCE(tx_desc->msg_type));
	dev_dbg(dev, "recv msg_type: %d\n", msg_type);

	srcid = le16_to_cpu(READ_ONCE(tx_desc->srcid));
	msgid = le16_to_cpu(READ_ONCE(tx_desc->msgid));

	if (msg_type >= NBL_CHAN_MSG_MAILBOX_MAX)
		return;

	data_len_fw = le16_to_cpu(READ_ONCE(tx_desc->data_len));
	if (data_len_fw) {
		payload_len = data_len_fw;

		if (payload_len > NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN) {
			dev_err_ratelimited(dev,
					    "data_len=%u exceeds embedded buffer size=%u\n",
					    payload_len,
					    NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN);
			return;
		}
		/* Small pkt: payload stored inside descriptor data[] array */
		payload = tx_desc->data;
	} else {
		payload_len = le16_to_cpu(READ_ONCE(tx_desc->buf_len));

		avail_space = NBL_CHAN_BUF_LEN - sizeof(*tx_desc);
		if (payload_len > avail_space) {
			dev_err_ratelimited(dev,
					    "buf_len=%u exceeds external buffer size=%zu\n",
					    payload_len, avail_space);
			return;
		}
		/* Large pkt: payload follows immediately after tx_desc */
		payload = tx_desc + 1;
	}

	msg_handler = nbl_common_get_hash_node(chan_mgt->handle_hash_tbl,
					       &msg_type);
	if (!msg_handler || !msg_handler->func) {
		dev_err_ratelimited(dev,
				    "No handler for msg_type: %u (srcid=%u, msgid=%u)\n",
				    msg_type, srcid, msgid);
		return;
	}

	msg_handler->func(msg_handler->priv, srcid, msgid, payload,
			  payload_len);
}

static void nbl_chan_advance_rx_ring(struct nbl_channel_mgt *chan_mgt,
				     struct nbl_chan_info *chan_info,
				     struct nbl_chan_ring *rxq)
{
	struct nbl_hw_ops *hw_ops = chan_mgt->hw_ops_tbl->ops;
	struct nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_buf *rx_buf;
	u16 next_to_use;

	next_to_use = rxq->next_to_use;
	rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_use);
	rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_use);

	/*
	 * Recycle the RX descriptor at next_to_use. The initial
	 * unused slot is intentionally recycled after the first
	 * RX descriptor is consumed, allowing the ring to become
	 * fully populated while next_to_clean tracks the consumer.
	 */
	rx_desc->buf_addr = cpu_to_le64(rx_buf->pa);
	rx_desc->buf_len = cpu_to_le32(chan_info->rxq_buf_size);

	/*
	 * DMA Write Memory Barrier:
	 * Ensures all previous DMA-mapped writes (buffer address/length)
	 * are completed before the descriptor flags are updated.
	 * This prevents hardware from seeing a partially updated descriptor
	 * where flags are set but buffer info isn't ready yet.
	 */
	dma_wmb();

	rx_desc->flags = cpu_to_le16(BIT(NBL_CHAN_RX_DESC_AVAIL));

	rxq->next_to_use++;
	if (rxq->next_to_use == chan_info->num_rxq_entries)
		rxq->next_to_use = 0;
	rxq->tail_ptr++;

	nbl_chan_update_tail_ptr(hw_ops, chan_mgt->hw_ops_tbl->priv,
				 rxq->tail_ptr, NBL_MB_RX_QID);
}

static void nbl_chan_clean_queue(struct nbl_channel_mgt *chan_mgt,
				 struct nbl_chan_info *chan_info)
{
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct device *dev = chan_mgt->common->dev;
	u32 budget = NBL_CHAN_RX_CLEAN_BUDGET;
	struct nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_buf *rx_buf;
	struct work_struct *task;
	bool more_work = false;
	u16 next_to_clean;
	u16 flags;

	next_to_clean = rxq->next_to_clean;
	rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_clean);
	rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_clean);
	while (le16_to_cpu(READ_ONCE(rx_desc->flags)) &
	       BIT(NBL_CHAN_RX_DESC_USED)) {
		flags = le16_to_cpu(READ_ONCE(rx_desc->flags));

		if (READ_ONCE(chan_info->shutdn))
			break;
		if (!(flags & BIT(NBL_CHAN_RX_DESC_WRITE)))
			dev_dbg(dev,
				"mailbox rx flag 0x%x missing NBL_CHAN_RX_DESC_WRITE\n",
				flags);

		/* Make sure hardware written descriptor visible to CPU */
		dma_rmb();
		nbl_chan_recv_msg(chan_mgt, rx_buf->va);
		nbl_chan_advance_rx_ring(chan_mgt, chan_info, rxq);
		next_to_clean++;
		if (next_to_clean == chan_info->num_rxq_entries)
			next_to_clean = 0;
		rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_clean);
		rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_clean);
		if (--budget == 0) {
			more_work = true;
			break;
		}
		cond_resched();
	}
	rxq->next_to_clean = next_to_clean;

	mutex_lock(&chan_info->state_lock);
	/* Prevent queue_work after teardown clears clean_task */
	if (READ_ONCE(chan_info->shutdn)) {
		mutex_unlock(&chan_info->state_lock);
		return;
	}
	if (common->wq && more_work) {
		task = READ_ONCE(chan_info->clean_task);
		if (task)
			queue_work(common->wq, task);
	}
	mutex_unlock(&chan_info->state_lock);
}

static void nbl_chan_clean_queue_subtask(struct nbl_channel_mgt *chan_mgt,
					 u8 chan_type)
{
	struct nbl_chan_info *chan_info = chan_mgt->chan_info[chan_type];

	nbl_chan_clean_queue(chan_mgt, chan_info);
}

static int nbl_chan_get_msg_id(struct nbl_chan_info *chan_info,
			       u16 *msgid)
{
	int search_loc = READ_ONCE(chan_info->wait_head_index), i;
	struct nbl_chan_waitqueue_head *wait = NULL;
	int status;
	int next;

	lockdep_assert_held(&chan_info->pending_lock);
	for (i = 0; i < chan_info->num_txq_entries; i++) {
		wait = &chan_info->wait[search_loc];
		status = READ_ONCE(wait->status);
		if (status == NBL_MBX_STATUS_IDLE ||
		    status == NBL_MBX_STATUS_TIMEOUT) {
			WRITE_ONCE(wait->msg_index,
				   NBL_NEXT_ID(wait->msg_index,
					       NBL_CHAN_MSG_INDEX_MAX));

			*msgid = FIELD_PREP(NBL_CHAN_MSGID_INDEX_MASK,
					    wait->msg_index) |
				 FIELD_PREP(NBL_CHAN_MSGID_LOC_MASK,
					    search_loc);

			/* Advance starting search position for next caller */
			next = NBL_NEXT_ID(search_loc,
					   chan_info->num_txq_entries - 1);
			WRITE_ONCE(chan_info->wait_head_index, next);
			return 0;
		}

		search_loc = NBL_NEXT_ID(search_loc,
					 chan_info->num_txq_entries - 1);
	}

	/*
	 * All tx slots are occupied. May happen under high transmit load
	 * or delayed remote ACK responses. Caller should retry later.
	 */
	return -EAGAIN;
}

static void nbl_chan_reset_wait_head(struct nbl_chan_info *chan_info,
				     struct nbl_chan_waitqueue_head *wait_head)
{
	lockdep_assert_held(&chan_info->pending_lock);

	WRITE_ONCE(wait_head->acked, 0);
	WRITE_ONCE(wait_head->status, NBL_MBX_STATUS_IDLE);
	WRITE_ONCE(wait_head->ack_data, NULL);
	WRITE_ONCE(wait_head->ack_data_len, 0);
	WRITE_ONCE(wait_head->ack_err, 0);
	WRITE_ONCE(wait_head->msg_type, 0);
	WRITE_ONCE(wait_head->dstid, 0);
}

static int nbl_chan_send_msg(struct nbl_channel_mgt *chan_mgt,
			     struct nbl_chan_send_info *chan_send)
{
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_chan_waitqueue_head *wait_head = NULL;
	struct nbl_chan_tx_param tx_param = { 0 };
	int i = NBL_CHAN_TX_WAIT_ACK_TIMES;
	struct nbl_chan_info *chan_info =
		chan_mgt->chan_info[NBL_CHAN_TYPE_MAILBOX];
	struct device *dev = common->dev;
	struct work_struct *task;
	u16 msgid = 0;
	int ret;

	if (chan_send->resp_len > NBL_CHAN_BUF_LEN) {
		dev_err_ratelimited(dev, "resp_len %zu exceeds max %d\n",
				    chan_send->resp_len, NBL_CHAN_BUF_LEN);
		return -EINVAL;
	}

	mutex_lock(&chan_info->state_lock);
	if (READ_ONCE(chan_info->shutdn)) {
		mutex_unlock(&chan_info->state_lock);
		return -ESHUTDOWN;
	}
	atomic_inc(&chan_info->inflight_tx_cnt);
	mutex_unlock(&chan_info->state_lock);

	tx_param.msg_type = chan_send->msg_type;
	tx_param.arg = chan_send->arg;
	tx_param.arg_len = chan_send->arg_len;
	tx_param.dstid = chan_send->dstid;
	tx_param.msgid = msgid;
	if (chan_send->ack) {
		mutex_lock(&chan_info->pending_lock);

		ret = nbl_chan_get_msg_id(chan_info, &msgid);
		if (ret) {
			mutex_unlock(&chan_info->pending_lock);
			dev_err_ratelimited(dev,
					    "Channel tx wait head full, send msgtype:%u to dstid:%u failed\n",
					    chan_send->msg_type,
					    chan_send->dstid);
			goto out_clean_inflight;
		}
		wait_head =
			&chan_info->wait[FIELD_GET(NBL_CHAN_MSGID_LOC_MASK,
						   msgid)];
		WRITE_ONCE(wait_head->acked, 0);
		WRITE_ONCE(wait_head->ack_data, chan_send->resp);
		WRITE_ONCE(wait_head->ack_data_len, chan_send->resp_len);
		WRITE_ONCE(wait_head->msg_type, chan_send->msg_type);
		WRITE_ONCE(wait_head->msg_index,
			   FIELD_GET(NBL_CHAN_MSGID_INDEX_MASK, msgid));
		WRITE_ONCE(wait_head->dstid, chan_send->dstid);

		WRITE_ONCE(wait_head->status, NBL_MBX_STATUS_WAITING);
		mutex_unlock(&chan_info->pending_lock);

		tx_param.msgid = msgid;
	}

	mutex_lock(&chan_info->txq_lock);
	ret = nbl_chan_update_txqueue(chan_mgt, chan_info, &tx_param);
	if (ret) {
		mutex_unlock(&chan_info->txq_lock);
		dev_err_ratelimited(dev,
				    "Channel tx queue full, send msgtype:%u to dstid:%u failed\n",
				    chan_send->msg_type, chan_send->dstid);
		if (wait_head)
			goto out_clear_wait_slot;
		goto out_clean_inflight;
	}

	ret = nbl_chan_kick_tx_ring(chan_mgt, chan_info);
	mutex_unlock(&chan_info->txq_lock);
	if (ret) {
		if (wait_head)
			goto out_clear_wait_slot;
		goto out_clean_inflight;
	}

	if (!chan_send->ack) {
		ret = 0;
		goto out_clean_inflight;
	}

	if (test_bit(NBL_CHAN_IRQ_RDY, chan_info->state)) {
		while (!READ_ONCE(wait_head->acked)) {
			/*
			 * avoids long task blocking when interrupt mode is
			 * disabled mid-wait. Cannot guarantee subsequent ACK
			 * delivery after interrupt mask off, only prevents
			 * infinite blocking. Spurious timeout is possible.
			 */
			ret = wait_event_timeout(wait_head->wait_queue,
						 READ_ONCE(wait_head->acked) ||
						 READ_ONCE(chan_info->shutdn) ||
						 !test_bit(NBL_CHAN_IRQ_RDY,
							   chan_info->state),
						 NBL_CHAN_ACK_WAIT_TIME);

			if (READ_ONCE(chan_info->shutdn)) {
				ret = -ESHUTDOWN;
				goto out_clear_wait_slot;
			}
			if (!test_bit(NBL_CHAN_IRQ_RDY, chan_info->state)) {
				ret = -EIO;
				goto out_clear_wait_slot;
			}
			if (ret == 0) {
				mutex_lock(&chan_info->pending_lock);
				if (READ_ONCE(wait_head->status) ==
				    NBL_MBX_STATUS_WAITING) {
					WRITE_ONCE(wait_head->status,
						   NBL_MBX_STATUS_TIMEOUT);
					WRITE_ONCE(wait_head->acked, 0);
					WRITE_ONCE(wait_head->ack_data, NULL);
					WRITE_ONCE(wait_head->ack_data_len, 0);
					/*
					 * Ensure all status/ack slot
					 * updates are visible before subsequent
					 * readers observe acked == 0
					 */
					smp_wmb();
				}
				mutex_unlock(&chan_info->pending_lock);
				dev_err_ratelimited(dev,
						    "Channel waiting ack failed, message type: %d, msg id: %u\n",
						    chan_send->msg_type, msgid);
				ret = -ETIMEDOUT;
				/*
				 * TIMEOUT slots can be reused by another
				 * sender. The current sender no longer
				 * owns the slot after transitioning it to
				 * TIMEOUT.
				 */
				goto out_clean_inflight;
			}

			if (READ_ONCE(wait_head->acked))
				break;
		}
		if (READ_ONCE(wait_head->acked)) {
			/*
			 * Load ordering: observe acked flag before
			 * reading ACK payload metadata.
			 */
			smp_rmb();
			chan_send->ack_len = READ_ONCE(wait_head->ack_data_len);
			ret = READ_ONCE(wait_head->ack_err);
		}
	} else {
		/* Polling path for synchronous ACK */
		while (i--) {
			if (READ_ONCE(chan_info->shutdn)) {
				ret = -ESHUTDOWN;
				goto out_clear_wait_slot;
			}

			mutex_lock(&chan_info->state_lock);
			task = READ_ONCE(chan_info->clean_task);
			if (common->wq && task &&
			    !READ_ONCE(chan_info->shutdn) &&
			    !work_pending(task))
				queue_work(common->wq, task);
			mutex_unlock(&chan_info->state_lock);
			if (READ_ONCE(wait_head->acked)) {
				/*
				 * Guarantee load order: observe acked
				 * flag before reading ack payload metadata.
				 */
				smp_rmb();
				chan_send->ack_len =
					READ_ONCE(wait_head->ack_data_len);
				ret = READ_ONCE(wait_head->ack_err);
				goto out_clear_wait_slot;
			}

			usleep_range(NBL_CHAN_TX_WAIT_ACK_US_MIN,
				     NBL_CHAN_TX_WAIT_ACK_US_MAX);
			cond_resched();
		}
		mutex_lock(&chan_info->pending_lock);
		if (READ_ONCE(wait_head->status) == NBL_MBX_STATUS_ACKD) {
			/* Ensure status load completes before ack payload/err
			 * loads.
			 */
			smp_rmb();
			chan_send->ack_len = READ_ONCE(wait_head->ack_data_len);
			ret = READ_ONCE(wait_head->ack_err);
			mutex_unlock(&chan_info->pending_lock);
			goto out_clear_wait_slot;
		}
		mutex_unlock(&chan_info->pending_lock);
		dev_err_ratelimited(dev,
				    "Channel polling ack failed, message type: %d msg id: %u\n",
				    chan_send->msg_type, msgid);
		ret = -ETIMEDOUT;
	}

out_clear_wait_slot:
	mutex_lock(&chan_info->pending_lock);
	nbl_chan_reset_wait_head(chan_info, wait_head);
	mutex_unlock(&chan_info->pending_lock);

out_clean_inflight:
	mutex_lock(&chan_info->state_lock);
	if (atomic_dec_and_test(&chan_info->inflight_tx_cnt))
		wake_up(&chan_info->inflight_wait);
	mutex_unlock(&chan_info->state_lock);
	return ret;
}

static int nbl_chan_send_ack(struct nbl_channel_mgt *chan_mgt,
			     struct nbl_chan_ack_info *chan_ack)
{
	size_t head_len = NBL_CHAN_ACK_HEAD_LEN * sizeof(u32);
	size_t data_len = chan_ack->data_len;
	struct nbl_chan_send_info chan_send;
	__le32 *tmp;
	size_t len;
	int ret;

	if (data_len >
	    NBL_CHAN_BUF_LEN - sizeof(struct nbl_chan_tx_desc) - head_len)
		return -EINVAL;

	len = head_len + data_len;
	tmp = kzalloc(len, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	*(__le16 *)&tmp[NBL_CHAN_MSG_TYPE_POS] =
		cpu_to_le16(chan_ack->msg_type);
	*(__le16 *)&tmp[NBL_CHAN_MSG_ID_POS] = cpu_to_le16(chan_ack->msgid);
	tmp[NBL_CHAN_ACK_RET_POS] = cpu_to_le32(chan_ack->err);
	if (chan_ack->data && chan_ack->data_len)
		memcpy(&tmp[NBL_CHAN_ACK_HEAD_LEN], chan_ack->data,
		       chan_ack->data_len);

	nbl_chan_fill_send_info(&chan_send, chan_ack->dstid, NBL_CHAN_MSG_ACK,
				tmp, len, NULL, 0, 0);
	ret = nbl_chan_send_msg(chan_mgt, &chan_send);
	kfree(tmp);

	return ret;
}

static int nbl_chan_register_msg(struct nbl_channel_mgt *chan_mgt, u16 msg_type,
				 nbl_chan_resp func, void *callback)
{
	return nbl_chan_add_msg_handler(chan_mgt, msg_type, func, callback);
}

static bool nbl_chan_check_queue_exist(struct nbl_channel_mgt *chan_mgt,
				       u8 chan_type)
{
	struct nbl_chan_info *chan_info = chan_mgt->chan_info[chan_type];

	return chan_info ? true : false;
}

static void nbl_chan_register_chan_task(struct nbl_channel_mgt *chan_mgt,
					u8 chan_type, struct work_struct *task)
{
	struct nbl_chan_info *chan_info = chan_mgt->chan_info[chan_type];

	mutex_lock(&chan_info->state_lock);
	if (!READ_ONCE(chan_info->shutdn))
		WRITE_ONCE(chan_info->clean_task, task);
	mutex_unlock(&chan_info->state_lock);
}

static void nbl_chan_set_queue_state(struct nbl_channel_mgt *chan_mgt,
				     enum nbl_chan_state state, u8 chan_type,
				     u8 set)
{
	struct nbl_chan_info *chan_info = chan_mgt->chan_info[chan_type];
	int i;

	if (set)
		set_bit(state, chan_info->state);
	else
		clear_bit(state, chan_info->state);
	/*
	 * When clearing IRQ_RDY, wake all per-slot wait queues so
	 * sleeping senders observe the condition immediately and
	 * return -EIO instead of waiting out the 3s timeout and
	 * reporting -ETIMEDOUT.
	 */
	if (!set && state == NBL_CHAN_IRQ_RDY) {
		for (i = 0; i < chan_info->num_txq_entries; i++)
			wake_up_all(&chan_info->wait[i].wait_queue);
	}
}

static struct nbl_channel_ops chan_ops = {
	.send_msg			= nbl_chan_send_msg,
	.send_ack			= nbl_chan_send_ack,
	.register_msg			= nbl_chan_register_msg,
	.unregister_all_msg		= nbl_chan_remove_msg_handler,
	.cfg_chan_qinfo_map_table	= nbl_chan_cfg_qinfo_map_table,
	.check_queue_exist		= nbl_chan_check_queue_exist,
	.setup_queue			= nbl_chan_setup_queue,
	.teardown_queue			= nbl_chan_teardown_queue,
	.clean_queue_subtask		= nbl_chan_clean_queue_subtask,
	.register_chan_task		= nbl_chan_register_chan_task,
	.set_queue_state		= nbl_chan_set_queue_state,
};

static struct nbl_channel_mgt *
nbl_chan_setup_chan_mgt(struct nbl_adapter *adapter)
{
	struct nbl_hw_ops_tbl *hw_ops_tbl = adapter->intf.hw_ops_tbl;
	struct nbl_common_info *common = &adapter->common;
	struct device *dev = &adapter->pdev->dev;
	struct nbl_channel_mgt *chan_mgt;
	struct nbl_chan_info *mailbox;
	int ret;

	chan_mgt = devm_kzalloc(dev, sizeof(*chan_mgt), GFP_KERNEL);
	if (!chan_mgt)
		return ERR_PTR(-ENOMEM);

	chan_mgt->common = common;
	chan_mgt->hw_ops_tbl = hw_ops_tbl;

	mailbox = devm_kzalloc(dev, sizeof(*mailbox), GFP_KERNEL);
	if (!mailbox)
		return ERR_PTR(-ENOMEM);
	mailbox->chan_type = NBL_CHAN_TYPE_MAILBOX;
	chan_mgt->chan_info[NBL_CHAN_TYPE_MAILBOX] = mailbox;

	ret = nbl_chan_init_msg_handler(chan_mgt);
	if (ret)
		return ERR_PTR(ret);
	ret = devm_mutex_init(common->dev, &mailbox->txq_lock);
	if (ret)
		return ERR_PTR(ret);
	ret = devm_mutex_init(common->dev, &mailbox->state_lock);
	if (ret)
		return ERR_PTR(ret);
	ret = devm_mutex_init(common->dev, &mailbox->pending_lock);
	if (ret)
		return ERR_PTR(ret);
	return chan_mgt;
}

static struct nbl_channel_ops_tbl *
nbl_chan_setup_ops(struct device *dev, struct nbl_channel_mgt *chan_mgt)
{
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	int ret;

	chan_ops_tbl = devm_kzalloc(dev, sizeof(*chan_ops_tbl), GFP_KERNEL);
	if (!chan_ops_tbl)
		return ERR_PTR(-ENOMEM);
	if (!chan_ops.send_msg || !chan_ops.send_ack ||
	    !chan_ops.register_msg || !chan_ops.unregister_all_msg ||
	    !chan_ops.cfg_chan_qinfo_map_table ||
	    !chan_ops.check_queue_exist || !chan_ops.setup_queue ||
	    !chan_ops.teardown_queue || !chan_ops.clean_queue_subtask ||
	    !chan_ops.register_chan_task || !chan_ops.set_queue_state)
		return ERR_PTR(-EINVAL);

	chan_ops_tbl->ops = &chan_ops;
	chan_ops_tbl->priv = chan_mgt;

	ret = nbl_chan_register_msg(chan_mgt, NBL_CHAN_MSG_ACK,
				    nbl_chan_recv_ack_msg, chan_mgt);
	if (ret)
		return ERR_PTR(ret);

	return chan_ops_tbl;
}

int nbl_chan_init_common(struct nbl_adapter *adap)
{
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct device *dev = &adap->pdev->dev;
	struct nbl_channel_mgt *chan_mgt;
	int ret;

	chan_mgt = nbl_chan_setup_chan_mgt(adap);
	if (IS_ERR(chan_mgt)) {
		ret = PTR_ERR(chan_mgt);
		goto exit;
	}

	chan_ops_tbl = nbl_chan_setup_ops(dev, chan_mgt);
	if (IS_ERR(chan_ops_tbl)) {
		ret = PTR_ERR(chan_ops_tbl);
		goto cleanup_mgt;
	}

	adap->intf.channel_ops_tbl = chan_ops_tbl;
	adap->core.chan_mgt = chan_mgt;
	ret = nbl_common_create_wq(&adap->common);
	if (ret)
		goto cleanup_mgt;
	return 0;

cleanup_mgt:
	nbl_chan_remove_msg_handler(chan_mgt);
exit:
	return ret;
}

void nbl_chan_remove_common(struct nbl_adapter *adap)
{
	struct nbl_channel_mgt *chan_mgt = adap->core.chan_mgt;

	if (!chan_mgt)
		return;
	nbl_common_destroy_wq(&adap->common);
	/*
	 * All channel queues shall be torn down earlier in remove path
	 * to drain inflight tx workers and stop hardware before destroying
	 * message handler hash table.
	 */
	nbl_chan_remove_msg_handler(chan_mgt);
	adap->core.chan_mgt = NULL;
}
