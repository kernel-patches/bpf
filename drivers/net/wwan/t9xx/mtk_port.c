// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "mtk_port.h"
#include "mtk_port_io.h"
#include "mtk_trans_ctrl.h"

#define MTK_DFLT_TRB_TIMEOUT		(5 * HZ)
#define MTK_DFLT_TRB_STATUS		(0x1)
#define MTK_CHECK_RX_SEQ_MASK		(0x7fff)
#define MTK_INVALID_RX_SEQ		(0xffff)

#define MTK_PORT_ENUM_VER		(0)
#define MTK_PORT_ENUM_HEAD_PATTERN	(0x5a5a5a5a)
#define MTK_PORT_ENUM_TAIL_PATTERN	(0xa5a5a5a5)

struct mtk_port_info {
	__le16 channel;
	__le16 reserved;
} __packed;

struct mtk_port_enum_msg {
	__le32 head_pattern;
	__le16 port_cnt;
	__le16 version;
	__le32 tail_pattern;
	u8 data[];
} __packed;

/* Returns NULL for an empty slot, or after restarting the walk at an
 * internal node; the caller then skips to the next slot.
 */
static struct mtk_port *mtk_port_tbl_slot(void __rcu ***slot, struct radix_tree_iter *iter)
{
	struct mtk_port *port = rcu_dereference_raw(**slot);

	if (radix_tree_is_internal_node(port)) {
		*slot = radix_tree_iter_retry(iter);
		return NULL;
	}

	return port;
}

/* Serialises a lookup and its kref_get() against the removal of the port
 * from the table and the kref_put() that may free it.
 */
DEFINE_MUTEX(mtk_port_mngr_grp_mtx);

/* Called with mtk_port_mngr_grp_mtx held. */
void mtk_port_release(struct kref *port_kref)
{
	struct mtk_port *port;

	port = container_of(port_kref, struct mtk_port, kref);
	mtk_port_get_ops(port->info.type)->exit(port);
	kfree_rcu(port, rcu);
}

static int mtk_port_tbl_add(struct mtk_port_mngr *port_mngr, struct mtk_port *port)
{
	int ret;

	mutex_lock(&port_mngr->port_tbl_mtx);
	ret = radix_tree_insert(&port_mngr->port_tbl[MTK_PORT_TBL_TYPE(port->info.rx_ch)],
				MTK_CH_ID(port->info.rx_ch), port);
	mutex_unlock(&port_mngr->port_tbl_mtx);

	if (ret)
		dev_err(port_mngr->ctrl_blk->mdev->dev,
			"port(%s) add to port_tbl failed, return %d\n",
			port->info.name, ret);

	return ret;
}

static void mtk_port_tbl_del(struct mtk_port_mngr *port_mngr, struct mtk_port *port)
{
	mutex_lock(&port_mngr->port_tbl_mtx);
	radix_tree_delete(&port_mngr->port_tbl[MTK_PORT_TBL_TYPE(port->info.rx_ch)],
			  MTK_CH_ID(port->info.rx_ch));
	mutex_unlock(&port_mngr->port_tbl_mtx);
}

static struct mtk_port *mtk_port_alloc_and_add(struct mtk_port_mngr *port_mngr,
					       const struct mtk_port_cfg *dflt_info)
{
	struct mtk_port *port;
	int ret;

	port = kzalloc_obj(*port, GFP_KERNEL);
	if (!port) {
		ret = -ENOMEM;
		goto err_alloc_port;
	}
	memcpy(&port->info, dflt_info, sizeof(*dflt_info));

	ret = mtk_port_tbl_add(port_mngr, port);
	if (ret < 0) {
		dev_err(port_mngr->ctrl_blk->mdev->dev,
			"Failed to add port(%s) to port tbl\n", dflt_info->name);
		goto err_free_port;
	}

	port->port_mngr = port_mngr;
	ret = mtk_port_get_ops(port->info.type)->init(port);
	if (ret < 0) {
		mtk_port_tbl_del(port_mngr, port);
		goto err_free_port;
	}

	return port;

err_free_port:
	kfree(port);
err_alloc_port:
	return ERR_PTR(ret);
}

static void mtk_port_free(struct mtk_port_mngr *port_mngr, struct mtk_port *port)
{
	mutex_lock(&mtk_port_mngr_grp_mtx);
	mtk_port_tbl_del(port_mngr, port);
	kref_put(&port->kref, mtk_port_release);
	mutex_unlock(&mtk_port_mngr_grp_mtx);
}

/* No lock: every caller runs in a context that is stopped before the control
 * plane destroys the port table.  A caller without that guarantee must use
 * mtk_port_get_by_name() instead.
 */
static struct mtk_port *mtk_port_search_by_id(struct mtk_port_mngr *port_mngr, int rx_ch)
{
	int tbl_type = MTK_PORT_TBL_TYPE(rx_ch);

	if (tbl_type < PORT_TBL_SAP || tbl_type >= PORT_TBL_MAX)
		return NULL;

	return radix_tree_lookup(&port_mngr->port_tbl[tbl_type], MTK_CH_ID(rx_ch));
}

static struct mtk_port *mtk_port_search_by_name(struct mtk_port_mngr *port_mngr,
						const char *name)
{
	int tbl_type = PORT_TBL_SAP;
	struct radix_tree_iter iter;
	struct mtk_port *port;
	void __rcu **slot;

	lockdep_assert_held(&mtk_port_mngr_grp_mtx);

	do {
		radix_tree_for_each_slot(slot, &port_mngr->port_tbl[tbl_type], &iter, 0) {
			port = mtk_port_tbl_slot(&slot, &iter);
			if (!port)
				continue;
			if (!strncmp(port->info.name, name, MTK_DFLT_PORT_NAME_LEN))
				return port;
		}
		tbl_type++;
	} while (tbl_type < PORT_TBL_MAX);

	return NULL;
}

struct mtk_port *mtk_port_get_by_name(struct mtk_port_mngr *port_mngr, const char *name,
				      enum mtk_port_type type)
{
	struct mtk_port *port;

	mutex_lock(&mtk_port_mngr_grp_mtx);
	port = mtk_port_search_by_name(port_mngr, name);
	if (port && port->info.type == type)
		kref_get(&port->kref);
	else
		port = NULL;
	mutex_unlock(&mtk_port_mngr_grp_mtx);

	return port;
}

static int mtk_port_tbl_create(struct mtk_port_mngr *port_mngr, const struct mtk_port_cfg *cfg,
			       const int port_cnt)
{
	const struct mtk_port_cfg *dflt_port;
	struct mtk_port *port;
	int i;

	INIT_RADIX_TREE(&port_mngr->port_tbl[PORT_TBL_SAP], GFP_KERNEL);
	INIT_RADIX_TREE(&port_mngr->port_tbl[PORT_TBL_MD], GFP_KERNEL);

	/* copy ports from static port cfg table */
	for (i = 0; i < port_cnt; i++) {
		dflt_port = cfg + i;
		if (!mtk_port_search_by_id(port_mngr, dflt_port->rx_ch)) {
			port = mtk_port_alloc_and_add(port_mngr, dflt_port);
			if (IS_ERR(port))
				return PTR_ERR(port);
		}
	}

	return 0;
}

static void mtk_port_tbl_destroy(struct mtk_port_mngr *port_mngr)
{
	struct radix_tree_iter iter;
	struct mtk_port *port;
	void __rcu **slot;
	int tbl_type;

	tbl_type = PORT_TBL_SAP;
	do {
		radix_tree_for_each_slot(slot, &port_mngr->port_tbl[tbl_type], &iter, 0) {
			port = mtk_port_tbl_slot(&slot, &iter);
			if (!port)
				continue;
			mtk_port_get_ops(port->info.type)->disable(port);
		}

		while (radix_tree_gang_lookup(&port_mngr->port_tbl[tbl_type],
					      (void **)&port, 0, 1))
			mtk_port_free(port_mngr, port);
	} while (++tbl_type < PORT_TBL_MAX);
}

void mtk_port_trb_init(struct mtk_port *port, struct trb *trb, enum mtk_trb_cmd_type cmd,
		       int (*trb_complete)(struct sk_buff *skb))
{
	kref_init(&trb->kref);
	trb->channel_id = port->info.rx_ch;
	trb->status = MTK_DFLT_TRB_STATUS;
	trb->done = false;
	/* No reference is taken: the port must outlive every trb that names
	 * it and every RX queue armed with this pointer as rxq->arg.
	 */
	trb->priv = port;
	trb->cmd = cmd;
	trb->trb_complete = trb_complete;
}

static bool mtk_port_trb_done(struct trb *trb)
{
	/* Pairs with the smp_store_release() in the completion callbacks. */
	return smp_load_acquire(&trb->done);
}

void mtk_port_trb_free(struct kref *trb_kref)
{
	struct trb *trb = container_of(trb_kref, struct trb, kref);

	dev_kfree_skb_any(container_of((char *)trb, struct sk_buff, cb[0]));
}

static int mtk_port_ch_trb_complete(struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct mtk_port *port = trb->priv;

	/* Pairs with the smp_load_acquire() of trb->done in the waiters. */
	smp_store_release(&trb->done, true);
	wake_up_all(&port->trb_wq);
	kref_put(&trb->kref, mtk_port_trb_free);

	return 0;
}

static int mtk_port_tx_complete(struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct mtk_port *port = trb->priv;

	if (trb->status < 0)
		dev_warn_ratelimited(port->port_mngr->ctrl_blk->mdev->dev,
				     "Failed to send data: status:%d, port:%s\n",
				     trb->status, port->info.name);

	/* Pairs with the smp_load_acquire() of trb->done in the waiters. */
	smp_store_release(&trb->done, true);
	wake_up_all(&port->trb_wq);
	kref_put(&trb->kref, mtk_port_trb_free);

	return 0;
}

int mtk_port_status_check(struct mtk_port *port)
{
	if (!test_bit(PORT_S_ENABLE, &port->status))
		return -ENODEV;

	if (!test_bit(PORT_S_OPEN, &port->status) || test_bit(PORT_S_FLUSH, &port->status) ||
	    !test_bit(PORT_S_WR, &port->status))
		return -EBADF;

	return 0;
}

int mtk_port_send_data(struct mtk_port *port, void *data, bool blocking, bool force_send)
{
	struct mtk_port_mngr *port_mngr;
	struct sk_buff *skb = data;
	struct trb *trb;
	int ret, len;

	port_mngr = port->port_mngr;

	trb = (struct trb *)skb->cb;
	mtk_port_trb_init(port, trb, TRB_CMD_TX, mtk_port_tx_complete);
	len = skb->len;
	kref_get(&trb->kref); /* kref count 1->2 */

	/* add ccci header */
	ret = mtk_port_add_header(skb);
	if (!ret)
		ret = mtk_port_status_check(port);
	if (!ret)
		ret = mtk_pcie_hif_submit_skb(port_mngr->ctrl_blk->mdev, skb,
					      force_send);

	if (ret < 0) {
		kref_put(&trb->kref, mtk_port_trb_free); /* kref count 2->1 */
		kref_put(&trb->kref, mtk_port_trb_free); /* kref count 1->0 */
		goto out;
	}

	if (!blocking) {
		kref_put(&trb->kref, mtk_port_trb_free);
		ret = len;
		goto out;
	}

	/* no timeout in tx blocking mode */
	ret = wait_event_interruptible(port->trb_wq,
				       mtk_port_trb_done(trb) ||
				       test_bit(PORT_S_FLUSH, &port->status) ||
				       !test_bit(PORT_S_WR, &port->status));
	/* Only a completed trb has a meaningful status; any other wake is
	 * a write failure.
	 */
	if (ret)
		ret = -EINTR;
	else if (mtk_port_trb_done(trb))
		ret = trb->status ? trb->status : len;
	else
		ret = -EBADF;
	kref_put(&trb->kref, mtk_port_trb_free);

out:
	return ret;
}

/* A gap only means an earlier packet was lost; this one is still delivered. */
static void mtk_port_check_rx_seq(struct mtk_port *port, struct mtk_ccci_header *ccci_h)
{
	u16 seq_num, assert_bit, channel;
	struct mtk_md_dev *mdev;

	seq_num = FIELD_GET(MTK_HDR_FLD_SEQ, le32_to_cpu(ccci_h->status));
	assert_bit = FIELD_GET(MTK_HDR_FLD_AST, le32_to_cpu(ccci_h->status));
	if (assert_bit && port->rx_seq != MTK_INVALID_RX_SEQ &&
	    ((seq_num - port->rx_seq) & MTK_CHECK_RX_SEQ_MASK) != 1) {
		mdev = port->port_mngr->ctrl_blk->mdev;
		channel = FIELD_GET(MTK_HDR_FLD_CHN, le32_to_cpu(ccci_h->status));
		dev_warn_ratelimited(mdev->dev,
				     "<ch: %04x> seq num out-of-order %d->%d, len(%u)\n",
				     channel, port->rx_seq, seq_num,
				     le32_to_cpu(ccci_h->packet_len));
	}
}

static int mtk_port_rx_dispatch(struct sk_buff *skb, void *priv)
{
	struct mtk_port_mngr *port_mngr;
	struct mtk_ccci_header *ccci_h;
	struct mtk_port *port = priv;
	int ret = -EPROTO;
	u16 channel;

	if (!skb || !priv) {
		pr_err("Invalid input value in rx dispatch\n");
		return -EINVAL;
	}

	port_mngr = port->port_mngr;

	ccci_h = mtk_port_strip_header(skb);
	if (unlikely(!ccci_h)) {
		dev_warn_ratelimited(port_mngr->ctrl_blk->mdev->dev,
				     "Unsupported: skb length(%u) is less than ccci header\n",
				     skb->len);
		goto drop_data;
	}

	channel = FIELD_GET(MTK_HDR_FLD_CHN, le32_to_cpu(ccci_h->status));
	/* A CLDMA instance carries the channels of one peer only (sAP or MD),
	 * the peer of the port that armed this queue.
	 */
	if (MTK_PEER_ID(channel) == MTK_PEER_ID(port->info.rx_ch))
		port = mtk_port_search_by_id(port_mngr, channel);
	else
		port = NULL;
	if (unlikely(!port)) {
		dev_warn_ratelimited(port_mngr->ctrl_blk->mdev->dev,
				     "Failed to find port by channel:%d\n", channel);
		goto drop_data;
	}

	mtk_port_check_rx_seq(port, ccci_h);
	port->rx_seq = FIELD_GET(MTK_HDR_FLD_SEQ, le32_to_cpu(ccci_h->status));

	ret = mtk_port_get_ops(port->info.type)->recv(port, skb);
	if (ret < 0)
		goto drop_data;

	return ret;

drop_data:
	dev_kfree_skb_any(skb);
	return ret;
}

int mtk_port_add_header(struct sk_buff *skb)
{
	struct mtk_ccci_header *ccci_h;
	struct mtk_port *port;
	struct trb *trb;
	int ret;

	trb = (struct trb *)skb->cb;
	port = trb->priv;
	if (!port)
		return -EINVAL;

	ret = skb_cow_head(skb, sizeof(*ccci_h));
	if (ret)
		return ret;

	ccci_h = skb_push(skb, sizeof(*ccci_h));

	ccci_h->packet_header = cpu_to_le32(0);
	ccci_h->packet_len = cpu_to_le32(skb->len);
	ccci_h->ex_msg = cpu_to_le32(0);
	/* SEQ is stamped at hand-off, see mtk_port_tx_seq_stamp() */
	ccci_h->status = cpu_to_le32(FIELD_PREP(MTK_HDR_FLD_CHN, port->info.tx_ch) |
				     FIELD_PREP(MTK_HDR_FLD_AST, 1));

	return 0;
}

/* Called around the hardware hand-off of a TX TRB, so a packet that
 * fails before it reaches the ring does not consume a number.
 */
void mtk_port_tx_seq_stamp(struct sk_buff *skb)
{
	struct mtk_ccci_header *ccci_h = (struct mtk_ccci_header *)skb->data;
	struct mtk_port *port = ((struct trb *)skb->cb)->priv;
	u32 status = le32_to_cpu(ccci_h->status) & ~MTK_HDR_FLD_SEQ;

	ccci_h->status = cpu_to_le32(status |
				     FIELD_PREP(MTK_HDR_FLD_SEQ, port->tx_seq));
}

void mtk_port_tx_seq_advance(struct sk_buff *skb)
{
	struct mtk_port *port = ((struct trb *)skb->cb)->priv;

	port->tx_seq++;
}

struct mtk_ccci_header *mtk_port_strip_header(struct sk_buff *skb)
{
	struct mtk_ccci_header *ccci_h;

	if (!pskb_may_pull(skb, sizeof(*ccci_h)))
		return NULL;

	ccci_h = (struct mtk_ccci_header *)skb->data;
	skb_pull(skb, sizeof(*ccci_h));

	return ccci_h;
}

int mtk_port_status_update(struct mtk_md_dev *mdev, void *data, u32 data_len)
{
	struct mtk_port_enum_msg *msg = data;
	struct mtk_port_info *port_info;
	struct mtk_port_mngr *port_mngr;
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_port *port;
	int port_id;
	u16 ch_id;

	if (unlikely(!mdev || !msg))
		return -EINVAL;

	if (data_len < sizeof(*msg))
		return -EPROTO;

	ctrl_blk = mdev->ctrl_blk;
	port_mngr = ctrl_blk->port_mngr;
	if (le16_to_cpu(msg->version) != MTK_PORT_ENUM_VER ||
	    le32_to_cpu(msg->head_pattern) != MTK_PORT_ENUM_HEAD_PATTERN ||
	    le32_to_cpu(msg->tail_pattern) != MTK_PORT_ENUM_TAIL_PATTERN)
		return -EPROTO;

	if (data_len < sizeof(*msg) +
	    le16_to_cpu(msg->port_cnt) * sizeof(*port_info))
		return -EPROTO;

	for (port_id = 0; port_id < le16_to_cpu(msg->port_cnt); port_id++) {
		port_info = (struct mtk_port_info *)(msg->data +
						   (sizeof(*port_info) * port_id));
		ch_id = FIELD_GET(MTK_INFO_FLD_CHID, le16_to_cpu(port_info->channel));
		port = mtk_port_search_by_id(port_mngr, ch_id);
		if (!port)
			continue;
		port->enable = FIELD_GET(MTK_INFO_FLD_EN, le16_to_cpu(port_info->channel));
	}

	return 0;
}

int mtk_port_ch_enable(struct mtk_port *port)
{
	struct mtk_port_mngr *port_mngr = port->port_mngr;
	struct trb_open_priv *trb_open_priv;
	struct sk_buff *skb;
	struct trb *trb;
	int ret;

	/* The modem restarts its sequence numbering with the channel, and
	 * the first packet after it is not checked.
	 */
	port->tx_seq = 0;
	port->rx_seq = MTK_INVALID_RX_SEQ;

	skb = __dev_alloc_skb(sizeof(*trb_open_priv), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	trb_open_priv = (struct trb_open_priv *)skb->data;
	trb_open_priv->rx_done = mtk_port_rx_dispatch;

	skb_put(skb, sizeof(struct trb_open_priv));
	trb = (struct trb *)skb->cb;
	mtk_port_trb_init(port, trb, TRB_CMD_ENABLE, mtk_port_ch_trb_complete);
	kref_get(&trb->kref);

	ret = mtk_pcie_hif_submit_skb(port_mngr->ctrl_blk->mdev, skb, true);
	if (ret) {
		dev_err(port_mngr->ctrl_blk->mdev->dev,
			"Failed to submit trb for port(%s), ret=%d\n",
			port->info.name, ret);
		kref_put(&trb->kref, mtk_port_trb_free);
		kref_put(&trb->kref, mtk_port_trb_free);
		return ret;
	}

	ret = wait_event_timeout(port->trb_wq, mtk_port_trb_done(trb),
				 MTK_DFLT_TRB_TIMEOUT);
	if (!ret) {
		ret = -ETIMEDOUT;
	} else {
		/* The trb->done acquire in mtk_port_trb_done() orders the
		 * geometry read below, on the -EBUSY completion too.  Pairs
		 * with the smp_store_release() of trb->status in mtk_cldma_open().
		 */
		ret = smp_load_acquire(&trb->status);

		/* -EBUSY means another user already owns the queue, and the
		 * geometry it reports is that queue's - also valid here.
		 */
		if (!ret || ret == -EBUSY)
			port->tx_mtu = trb_open_priv->tx_mtu - MTK_CCCI_H_ELEN;
	}

	kref_put(&trb->kref, mtk_port_trb_free);

	return ret;
}

int mtk_port_ch_disable(struct mtk_port *port)
{
	struct mtk_port_mngr *port_mngr = port->port_mngr;
	struct sk_buff *skb;
	struct trb *trb;
	int ret;

	skb = __dev_alloc_skb(0, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	trb = (struct trb *)skb->cb;
	mtk_port_trb_init(port, trb, TRB_CMD_DISABLE, mtk_port_ch_trb_complete);
	kref_get(&trb->kref);

	ret = mtk_pcie_hif_submit_skb(port_mngr->ctrl_blk->mdev, skb, true);
	if (ret) {
		dev_warn(port_mngr->ctrl_blk->mdev->dev,
			 "Failed to submit trb for port(%s), ret=%d\n",
			 port->info.name, ret);
		kref_put(&trb->kref, mtk_port_trb_free);
		kref_put(&trb->kref, mtk_port_trb_free);
		return ret;
	}

	ret = wait_event_timeout(port->trb_wq, mtk_port_trb_done(trb),
				 MTK_DFLT_TRB_TIMEOUT);
	if (!ret)
		ret = -ETIMEDOUT;
	else
		ret = trb->status;

	kref_put(&trb->kref, mtk_port_trb_free);

	return ret;
}

int mtk_port_mngr_init(struct mtk_ctrl_blk *ctrl_blk, const struct mtk_port_cfg *port_cfg,
		       int port_cnt)
{
	struct mtk_port_mngr *port_mngr;
	int ret = -ENOMEM;

	port_mngr = devm_kzalloc(ctrl_blk->mdev->dev, sizeof(*port_mngr), GFP_KERNEL);
	if (unlikely(!port_mngr)) {
		dev_err((ctrl_blk->mdev)->dev, "Failed to alloc memory for port_mngr\n");
		goto err_out;
	}

	port_mngr->ctrl_blk = ctrl_blk;
	mutex_init(&port_mngr->port_tbl_mtx);

	ret = mtk_port_tbl_create(port_mngr, port_cfg, port_cnt);
	if (unlikely(ret)) {
		dev_err((ctrl_blk->mdev)->dev, "Failed to create port_tbl\n");
		goto err_destroy_tbl;
	}

	ctrl_blk->port_mngr = port_mngr;

	return ret;

err_destroy_tbl:
	mtk_port_tbl_destroy(port_mngr);
err_out:
	return ret;
}

void mtk_port_mngr_exit(struct mtk_ctrl_blk *ctrl_blk)
{
	struct mtk_port_mngr *port_mngr = ctrl_blk->port_mngr;

	mtk_port_tbl_destroy(port_mngr);

	ctrl_blk->port_mngr = NULL;
}
