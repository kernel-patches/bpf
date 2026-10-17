// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */
#include <linux/netdevice.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/wwan.h>

#include "mtk_port_io.h"
#include "mtk_trans_ctrl.h"

static void mtk_port_put_locked(struct mtk_port *port)
{
	mutex_lock(&mtk_port_mngr_grp_mtx);
	kref_put(&port->kref, mtk_port_release);
	mutex_unlock(&mtk_port_mngr_grp_mtx);
}

static void mtk_port_struct_init(struct mtk_port *port)
{
	clear_bit(PORT_S_ENABLE, &port->status);
	kref_init(&port->kref);
	skb_queue_head_init(&port->rx_skb_list);
	port->rx_buf_size = MTK_RX_BUF_SIZE;
	init_waitqueue_head(&port->trb_wq);
	init_waitqueue_head(&port->rx_wq);
}

/* Packets after the first carry force_send, which bypasses the HIF depth
 * check, so one write() must not exceed one queue depth.
 */
#define MTK_PORT_MAX_TX_PKT	SKB_LIST_MAX_LEN

/* Every packet is built before any is submitted: the WWAN core turns a
 * partial write into a whole-write failure and userspace re-sends the whole
 * message, so a submit that fails midway leaves a prefix on the wire.  It
 * cannot be retried here - the skb is freed with its trb - so it is logged.
 *
 * -EINTR means the skb was already submitted, so that packet counts as
 * accepted and the remaining ones are still sent.
 */
static int mtk_port_common_write(struct mtk_port *port, struct sk_buff *src, bool blocking)
{
	u32 packet_size, left_cnt = src->len, cur_pos;
	u32 payload_mtu, sent_len = 0;
	struct sk_buff_head list;
	bool force_send = blocking;
	struct sk_buff *skb;
	int ret;

	ret = mtk_port_status_check(port);
	if (ret)
		return ret;

	payload_mtu = port->tx_mtu - sizeof(struct mtk_ccci_header);
	if (src->len > MTK_PORT_MAX_TX_PKT * payload_mtu)
		return -EMSGSIZE;

	__skb_queue_head_init(&list);

	while (left_cnt) {
		skb = __dev_alloc_skb(port->tx_mtu, GFP_KERNEL);
		if (!skb) {
			ret = -ENOMEM;
			goto err_purge;
		}

		skb_reserve(skb, sizeof(struct mtk_ccci_header));

		packet_size = min_t(u32, left_cnt, payload_mtu);
		cur_pos = src->len - left_cnt;
		ret = skb_copy_bits(src, cur_pos, skb_put(skb, packet_size), packet_size);
		if (ret) {
			dev_err(port->port_mngr->ctrl_blk->mdev->dev,
				"Failed to copy data for port(%s)\n", port->info.name);
			dev_kfree_skb_any(skb);
			goto err_purge;
		}

		__skb_queue_tail(&list, skb);
		left_cnt -= packet_size;
	}

	while ((skb = __skb_dequeue(&list))) {
		/* mtk_port_send_data() may free the skb, so sample its length
		 * while it is still valid.
		 */
		packet_size = skb->len;

		ret = mtk_port_send_data(port, skb, blocking, force_send);
		if (ret < 0 && ret != -EINTR)
			goto err_submit;

		sent_len += packet_size;
		force_send = true;
	}

	return 0;

err_submit:
	if (sent_len)
		dev_err_ratelimited(port->port_mngr->ctrl_blk->mdev->dev,
				    "Partial write on port(%s): %u of %u bytes sent, error:%d\n",
				    port->info.name, sent_len, src->len, ret);
err_purge:
	__skb_queue_purge(&list);
	return ret;
}

static int mtk_port_internal_init(struct mtk_port *port)
{
	mtk_port_struct_init(port);
	port->enable = false;

	return 0;
}

static void mtk_port_internal_exit(struct mtk_port *port)
{
	if (test_bit(PORT_S_ENABLE, &port->status))
		mtk_port_get_ops(port->info.type)->disable(port);
}

static void mtk_port_internal_enable(struct mtk_port *port)
{
	int ret;

	if (test_bit(PORT_S_ENABLE, &port->status))
		return;

	ret = mtk_port_ch_enable(port);
	if (ret && ret != -EBUSY) {
		/* On -ETIMEDOUT the ENABLE trb may still be queued; queue a
		 * DISABLE behind it so the channel does not end up armed with
		 * no software owner.
		 */
		mtk_port_ch_disable(port);
		return;
	}

	set_bit(PORT_S_WR, &port->status);
	set_bit(PORT_S_ENABLE, &port->status);
}

static void mtk_port_internal_disable(struct mtk_port *port)
{
	int ret;

	if (!test_and_clear_bit(PORT_S_ENABLE, &port->status))
		return;

	/* PORT_S_WR is part of the blocking TX wait condition, and the waiter
	 * loops back on timeout, so without this wake it only notices at the
	 * next trb timeout rather than now.
	 */
	clear_bit(PORT_S_WR, &port->status);
	wake_up_all(&port->trb_wq);

	/* Failure must not abort teardown or keep PORT_S_ENABLE set:
	 * usr_cnt and the queues are rebuilt together at the next
	 * FSM_STATE_ON, and a port left with the bit set could never
	 * be re-enabled (mtk_port_internal_enable() early-returns).
	 */
	ret = mtk_port_ch_disable(port);
	if (ret)
		dev_warn(port->port_mngr->ctrl_blk->mdev->dev,
			 "Failed to disable channel for port(%s): %d\n",
			 port->info.name, ret);
}

static int mtk_port_internal_recv(struct mtk_port *port, struct sk_buff *skb)
{
	struct mtk_internal_port *priv;
	int ret = -ENXIO;

	if (!test_bit(PORT_S_OPEN, &port->status))
		goto drop_data;

	priv = &port->i_priv;
	if (!priv->recv_cb || !priv->arg)
		goto drop_data;

	ret = priv->recv_cb(priv->arg, skb);
	return ret;

drop_data:
	return ret;
}

static int mtk_port_common_open(struct mtk_port *port)
{
	int ret = 0;

	if (!test_bit(PORT_S_ENABLE, &port->status))
		return -ENODEV;

	if (test_bit(PORT_S_OPEN, &port->status))
		return -EBUSY;

	skb_queue_purge(&port->rx_skb_list);
	set_bit(PORT_S_OPEN, &port->status);
	clear_bit(PORT_S_FLUSH, &port->status);

	return ret;
}

static void mtk_port_common_close(struct mtk_port *port)
{
	clear_bit(PORT_S_OPEN, &port->status);

	skb_queue_purge(&port->rx_skb_list);
	port->rx_data_len = 0;

	set_bit(PORT_S_FLUSH, &port->status);
	wake_up_all(&port->trb_wq);
	wake_up_all(&port->rx_wq);
}

void *mtk_port_internal_open(struct mtk_md_dev *mdev, char *name, int flag)
{
	struct mtk_port_mngr *port_mngr;
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_port *port;
	int ret;

	ctrl_blk = mdev->ctrl_blk;
	port_mngr = ctrl_blk->port_mngr;

	port = mtk_port_get_by_name(port_mngr, name, PORT_TYPE_INTERNAL);
	if (!port)
		goto out;

	ret = mtk_port_common_open(port);
	if (ret) {
		mtk_port_put_locked(port);
		port = NULL;
		goto out;
	}

	if (flag & O_NONBLOCK)
		port->info.flags &= ~PORT_F_BLOCKING;
	else
		port->info.flags |= PORT_F_BLOCKING;
out:
	return port;
}

int mtk_port_internal_close(void *i_port)
{
	struct mtk_port *port = i_port;
	int ret = 0;

	if (!port) {
		ret = -EINVAL;
		goto end;
	}

	if (!test_bit(PORT_S_OPEN, &port->status)) {
		pr_err("Port(%s) has been closed\n", port->info.name);
		ret = -EBADF;
		goto end;
	}

	mtk_port_common_close(port);
	mtk_port_put_locked(port);
end:
	return ret;
}

int mtk_port_internal_write(void *i_port, struct sk_buff *skb)
{
	struct mtk_port *port = i_port;
	bool blocking;

	if (!port || !skb) {
		if (skb)
			dev_kfree_skb_any(skb);
		pr_err_ratelimited("Internal write: invalid input\n");
		return -EINVAL;
	}

	blocking = !!(port->info.flags & PORT_F_BLOCKING);

	return mtk_port_send_data(port, skb, blocking, blocking);
}

void mtk_port_internal_recv_register(void *i_port,
				     int (*cb)(void *priv, struct sk_buff *skb),
				     void *arg)
{
	struct mtk_port *port = i_port;
	struct mtk_internal_port *priv;

	priv = &port->i_priv;
	priv->arg = arg;
	priv->recv_cb = cb;
}

static const struct mtk_port_ops port_internal_ops = {
	.init = mtk_port_internal_init,
	.exit = mtk_port_internal_exit,
	.enable = mtk_port_internal_enable,
	.disable = mtk_port_internal_disable,
	.recv = mtk_port_internal_recv,
};

static void mtk_port_get_locked(struct mtk_port *port)
{
	mutex_lock(&mtk_port_mngr_grp_mtx);
	kref_get(&port->kref);
	mutex_unlock(&mtk_port_mngr_grp_mtx);
}

static int mtk_port_wwan_open(struct wwan_port *w_port)
{
	struct mtk_port *port;
	int ret;

	port = wwan_port_get_drvdata(w_port);
	mtk_port_get_locked(port);

	/* mtk_port_common_open() is what sets PORT_S_OPEN, and the RX path
	 * tests it together with w_port, so both are published under w_lock.
	 */
	mutex_lock(&port->w_priv.w_lock);
	ret = mtk_port_common_open(port);
	if (!ret)
		port->w_priv.w_port = w_port;
	mutex_unlock(&port->w_priv.w_lock);
	if (ret) {
		mtk_port_put_locked(port);
		return ret;
	}

	/* WWAN_PORT_TX_OFF persists on the wwan_port across close/open
	 * cycles; start every session writable.
	 */
	wwan_port_txon(w_port);

	return 0;
}

static void mtk_port_wwan_close(struct wwan_port *w_port)
{
	struct mtk_port *port = wwan_port_get_drvdata(w_port);

	/* Clear PORT_S_OPEN under the same lock mtk_port_wwan_recv() holds, so
	 * a receive that saw the port open has finished its wwan_port_rx()
	 * before stop() returns and the core purges its rx queue.
	 */
	mutex_lock(&port->w_priv.w_lock);
	mtk_port_common_close(port);
	mutex_unlock(&port->w_priv.w_lock);

	mtk_port_put_locked(port);
}

/* Pause TX after a queue-full submit failure.  The queue may have drained
 * between that failure and the txoff below, and that tx_complete is lost, so
 * recheck and undo the txoff if the queue is no longer full.
 *
 * w_lock is dropped for the recheck to keep it a leaf with respect to
 * trans->submit_lock.  A tx_complete landing in the gap can only add a txon,
 * so TX is never left off with nothing to wake it.
 */
static void mtk_port_wwan_tx_pause(struct mtk_port *port)
{
	union ctrl_hif_cmd_data hif_cmd;
	struct mtk_ctrl_blk *ctrl_blk;
	int ret;

	ctrl_blk = port->port_mngr->ctrl_blk;

	mutex_lock(&port->w_priv.w_lock);
	if (!port->w_priv.w_port) {
		mutex_unlock(&port->w_priv.w_lock);
		return;
	}

	wwan_port_txoff(port->w_priv.w_port);
	mutex_unlock(&port->w_priv.w_lock);

	hif_cmd.rx_ch = port->info.rx_ch;
	ret = mtk_pcie_hif_cmd_func(ctrl_blk->mdev, HIF_CTRL_CMD_CHECK_TX_FULL,
				    &hif_cmd);
	if (ret > 0)
		return;

	mutex_lock(&port->w_priv.w_lock);
	if (port->w_priv.w_port)
		wwan_port_txon(port->w_priv.w_port);
	mutex_unlock(&port->w_priv.w_lock);
}

/* w_lock closes the txoff-after-drain window described in
 * mtk_port_wwan_tx_pause().
 */
static void mtk_port_wwan_tx_complete(struct mtk_port *port)
{
	mutex_lock(&port->w_priv.w_lock);
	if (port->w_priv.w_port)
		wwan_port_txon(port->w_priv.w_port);
	mutex_unlock(&port->w_priv.w_lock);
}

static int mtk_port_wwan_tx(struct wwan_port *w_port, struct sk_buff *skb, bool blocking)
{
	struct mtk_port *port = wwan_port_get_drvdata(w_port);
	int ret;

	if (unlikely(!skb->len)) {
		consume_skb(skb);
		return 0;
	}

	ret = mtk_port_common_write(port, skb, blocking);
	if (ret < 0) {
		if (ret == -EAGAIN)
			mtk_port_wwan_tx_pause(port);
		return ret;
	}

	consume_skb(skb);
	return 0;
}

static int mtk_port_wwan_write(struct wwan_port *w_port, struct sk_buff *skb)
{
	return mtk_port_wwan_tx(w_port, skb, false);
}

static int mtk_port_wwan_write_blocking(struct wwan_port *w_port, struct sk_buff *skb)
{
	return mtk_port_wwan_tx(w_port, skb, true);
}

/* No .tx_poll: it would poll_wait() on port->trb_wq, which lives in a
 * mtk_port that wwan_remove_port() lets go of while the file stays open,
 * and wake_up_pollfree() is not available to modules.  TX back-pressure
 * reaches poll() through wwan_port_txon()/txoff() on the core's own
 * waitqueue instead, whose lifetime is pinned by the open file.
 */
static const struct wwan_port_ops wwan_ops = {
	.start = mtk_port_wwan_open,
	.stop = mtk_port_wwan_close,
	.tx = mtk_port_wwan_write,
	.tx_blocking = mtk_port_wwan_write_blocking,
};

static int mtk_port_wwan_init(struct mtk_port *port)
{
	mtk_port_struct_init(port);
	port->enable = false;

	mutex_init(&port->w_priv.w_lock);

	switch (port->info.rx_ch) {
	case CCCI_MBIM_RX:
		port->w_priv.w_type = WWAN_PORT_MBIM;
		break;
	case CCCI_UART2_RX:
		port->w_priv.w_type = WWAN_PORT_AT;
		break;
	default:
		port->w_priv.w_type = WWAN_PORT_UNKNOWN;
		break;
	}

	return 0;
}

static void mtk_port_wwan_exit(struct mtk_port *port)
{
	if (test_bit(PORT_S_ENABLE, &port->status))
		mtk_port_get_ops(port->info.type)->disable(port);
}

static void mtk_port_wwan_enable(struct mtk_port *port)
{
	struct mtk_port_mngr *port_mngr;
	struct wwan_port_caps caps;
	struct wwan_port *wp;
	int ret;

	port_mngr = port->port_mngr;

	if (test_bit(PORT_S_ENABLE, &port->status))
		return;

	ret = mtk_port_ch_enable(port);
	if (ret && ret != -EBUSY) {
		/* On -ETIMEDOUT the enable's outcome is not yet known: the
		 * ENABLE trb may still be queued.  The DISABLE is queued
		 * behind it, so the channel cannot stay armed unowned.
		 */
		mtk_port_ch_disable(port);
		return;
	}

	/* A zero frag_len would make wwan_port_fops_write() loop forever. */
	if (!port->tx_mtu) {
		dev_err(port_mngr->ctrl_blk->mdev->dev,
			"Invalid tx_mtu for port(%s)\n", port->info.name);
		mtk_port_ch_disable(port);
		return;
	}

	/* The core allocates frag_len + headroom_len and skb_put()s frag_len,
	 * so frag_len is the payload budget: subtract the CCCI header to make
	 * one core fragment exactly one CCCI packet.
	 */
	caps.frag_len = port->tx_mtu - sizeof(struct mtk_ccci_header);
	caps.headroom_len = sizeof(struct mtk_ccci_header);

	/* These bits must be set before wwan_create_port(): the device node
	 * becomes openable inside it and mtk_port_common_open() rejects a
	 * port without PORT_S_ENABLE.
	 */
	set_bit(PORT_S_WR, &port->status);
	set_bit(PORT_S_ENABLE, &port->status);

	wp = wwan_create_port(port_mngr->ctrl_blk->mdev->dev,
			      port->w_priv.w_type,
			      &wwan_ops, &caps, port);
	if (IS_ERR(wp)) {
		dev_warn(port_mngr->ctrl_blk->mdev->dev,
			 "Failed to create wwan port for (%s)\n", port->info.name);
		clear_bit(PORT_S_ENABLE, &port->status);
		clear_bit(PORT_S_WR, &port->status);
		mtk_port_ch_disable(port);
		return;
	}

	/* .start publishes w_port for an opened node; this covers the node
	 * nobody opened, which still needs w_port to be removed.
	 */
	mutex_lock(&port->w_priv.w_lock);
	port->w_priv.w_port = wp;
	mutex_unlock(&port->w_priv.w_lock);
}

static void mtk_port_wwan_disable(struct mtk_port *port)
{
	struct wwan_port *w_port;
	int ret;

	if (!test_and_clear_bit(PORT_S_ENABLE, &port->status))
		return;

	/* PORT_S_WR is part of the blocking TX wait condition, and the waiter
	 * loops back on timeout, so without this wake it only notices at the
	 * next trb timeout rather than now.
	 */
	clear_bit(PORT_S_WR, &port->status);
	wake_up_all(&port->trb_wq);

	/* w_lock must be dropped before wwan_remove_port(): that takes the
	 * core's ops_lock and forces stop(), which is close() taking w_lock.
	 */
	mutex_lock(&port->w_priv.w_lock);
	w_port = port->w_priv.w_port;
	port->w_priv.w_port = NULL;
	mutex_unlock(&port->w_priv.w_lock);

	ret = mtk_port_ch_disable(port);
	if (ret)
		dev_warn(port->port_mngr->ctrl_blk->mdev->dev,
			 "Failed to disable channel for port(%s): %d\n",
			 port->info.name, ret);

	wwan_remove_port(w_port);
}

static int mtk_port_wwan_recv(struct mtk_port *port, struct sk_buff *skb)
{
	/* Drop frames when nobody has the device open: wwan_port_rx() queues
	 * without bound and only a reader drains the queue, so accepting
	 * unsolicited traffic here would grow the rxq indefinitely.  Both
	 * conditions are read under w_lock, which mtk_port_wwan_close() also
	 * takes, so a frame accepted here cannot land on a queue the core is
	 * about to purge.
	 */
	mutex_lock(&port->w_priv.w_lock);
	if (!test_bit(PORT_S_OPEN, &port->status) || !port->w_priv.w_port) {
		mutex_unlock(&port->w_priv.w_lock);
		dev_dbg_ratelimited(port->port_mngr->ctrl_blk->mdev->dev,
				    "Drop RX for unopened port(%s)\n", port->info.name);
		return -ENXIO;
	}

	wwan_port_rx(port->w_priv.w_port, skb);
	mutex_unlock(&port->w_priv.w_lock);
	return 0;
}

static const struct mtk_port_ops port_wwan_ops = {
	.init = mtk_port_wwan_init,
	.exit = mtk_port_wwan_exit,
	.enable = mtk_port_wwan_enable,
	.disable = mtk_port_wwan_disable,
	.recv = mtk_port_wwan_recv,
	.tx_complete = mtk_port_wwan_tx_complete,
};

static const struct mtk_port_ops *mtk_port_ops_tbl[PORT_TYPE_MAX] = {
	&port_internal_ops,
	&port_wwan_ops,
};

const struct mtk_port_ops *mtk_port_get_ops(enum mtk_port_type type)
{
	return mtk_port_ops_tbl[type];
}
