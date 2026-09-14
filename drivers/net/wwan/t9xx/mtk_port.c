// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "mtk_port.h"
#include "mtk_port_io.h"

#define MTK_DFLT_TRB_TIMEOUT		(5 * HZ)
#define MTK_DFLT_TRB_STATUS		(0x1)
#define MTK_TRB_HEADER_ADDED		(0xADDED)
#define MTK_CHECK_RX_SEQ_MASK		(0x7fff)

#define MTK_PORT_ENUM_VER		(0)
#define MTK_PORT_ENUM_HEAD_PATTERN	(0x5a5a5a5a)
#define MTK_PORT_ENUM_TAIL_PATTERN	(0xa5a5a5a5)

#define MTK_PORT_SEARCH_FROM_RADIX_TREE(p, s) ({\
	struct mtk_port *_p;			\
	_p = rcu_dereference_raw(*(s));		\
	if (!_p)				\
		continue;			\
	p = _p;					\
})

#define MTK_PORT_INTERNAL_NODE_CHECK(p, s, i) ({\
	if (radix_tree_is_internal_node(p)) {	\
		s = radix_tree_iter_retry(&(i));\
		continue;			\
	}					\
})

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

/* global group for stale ports */
static LIST_HEAD(stale_list_grp);
/* mutex lock for stale_list_group */
DEFINE_MUTEX(port_mngr_grp_mtx);

static DEFINE_IDA(ccci_dev_ids);

/* This function working always under mutex lock port_mngr_grp_mtx */
void mtk_port_release(struct kref *port_kref)
{
	struct mtk_stale_list *s_list;
	struct mtk_port *port;

	port = container_of(port_kref, struct mtk_port, kref);
	if (!test_bit(PORT_S_ON_STALE_LIST, &port->status))
		goto port_exit;

	list_del(&port->stale_entry);
	list_for_each_entry(s_list, &stale_list_grp, entry) {
		if (!strncmp(s_list->dev_str, port->dev_str, MTK_DEV_STR_LEN) &&
		    list_empty(&s_list->ports) && s_list->dev_id >= 0) {
			ida_free(&ccci_dev_ids, s_list->dev_id);
			s_list->dev_id = -1;
			break;
		}
	}
port_exit:
	ports_ops[port->info.type]->exit(port);
	kfree(port);
}

static int mtk_port_tbl_add(struct mtk_port_mngr *port_mngr, struct mtk_port *port)
{
	int ret;

	ret = radix_tree_insert(&port_mngr->port_tbl[MTK_PORT_TBL_TYPE(port->info.rx_ch)],
				port->info.rx_ch & 0xFFF, port);
	if (ret)
		dev_err(port_mngr->ctrl_blk->mdev->dev,
			"port(%s) add to port_tbl failed, return %d\n",
			port->info.name, ret);
	else
		port_mngr->port_cnt++;

	return ret;
}

static void mtk_port_tbl_del(struct mtk_port_mngr *port_mngr, struct mtk_port *port)
{
	radix_tree_delete(&port_mngr->port_tbl[MTK_PORT_TBL_TYPE(port->info.rx_ch)],
			  port->info.rx_ch & 0xFFF);
	port_mngr->port_cnt--;
}

static struct mtk_port *mtk_port_restore_from_stale_list(struct mtk_port_mngr *port_mngr,
							 struct mtk_stale_list *s_list)
{
	struct mtk_port *port, *next_port;
	int ret;

	mutex_lock(&port_mngr_grp_mtx);
	list_for_each_entry_safe(port, next_port, &s_list->ports, stale_entry) {
		kref_get(&port->kref);
		list_del(&port->stale_entry);
		ret = mtk_port_tbl_add(port_mngr, port);
		if (ret) {
			list_add_tail(&port->stale_entry, &s_list->ports);
			kref_put(&port->kref, mtk_port_release);
			mutex_unlock(&port_mngr_grp_mtx);
			dev_err(port_mngr->ctrl_blk->mdev->dev,
				"Failed when adding (%s) to port mngr\n",
				port->info.name);
			return ERR_PTR(ret);
		}

		port->port_mngr = port_mngr;
		clear_bit(PORT_S_ON_STALE_LIST, &port->status);
		ports_ops[port->info.type]->reset(port);
	}
	mutex_unlock(&port_mngr_grp_mtx);

	return NULL;
}

static struct mtk_port *mtk_port_alloc_and_add(struct mtk_port_mngr *port_mngr,
					       struct mtk_port_cfg *dflt_info)
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
	ret = ports_ops[port->info.type]->init(port);
	if (ret < 0) {
		mtk_port_tbl_del(port_mngr, port);
		goto err_free_port;
	}

	memcpy(port->dev_str, port_mngr->ctrl_blk->mdev->dev_str, MTK_DEV_STR_LEN);
	return port;

err_free_port:
	kfree(port);
err_alloc_port:
	return ERR_PTR(ret);
}

static void mtk_port_free_or_backup(struct mtk_port_mngr *port_mngr,
				    struct mtk_port *port, struct mtk_stale_list *s_list)
{
	mutex_lock(&port_mngr_grp_mtx);
	mtk_port_tbl_del(port_mngr, port);
	if (port->info.type != PORT_TYPE_INTERNAL) {
		if (test_bit(PORT_S_OPEN, &port->status)) {
			list_add_tail(&port->stale_entry, &s_list->ports);
			set_bit(PORT_S_ON_STALE_LIST, &port->status);
			memcpy(port->dev_str, port_mngr->ctrl_blk->mdev->dev_str,
			       MTK_DEV_STR_LEN);
			port->port_mngr = NULL;
		}
		kref_put(&port->kref, mtk_port_release);
	} else {
		kref_put(&port->kref, mtk_port_release);
	}
	mutex_unlock(&port_mngr_grp_mtx);
}

static struct mtk_port *mtk_port_search_by_id(struct mtk_port_mngr *port_mngr, int rx_ch)
{
	int tbl_type = MTK_PORT_TBL_TYPE(rx_ch);

	if (tbl_type < PORT_TBL_SAP || tbl_type >= PORT_TBL_MAX)
		return NULL;

	return radix_tree_lookup(&port_mngr->port_tbl[tbl_type], MTK_CH_ID(rx_ch));
}

struct mtk_port *mtk_port_search_by_name(struct mtk_port_mngr *port_mngr, char *name)
{
	int tbl_type = PORT_TBL_SAP;
	struct radix_tree_iter iter;
	struct mtk_port *port;
	void __rcu **slot;

	do {
		radix_tree_for_each_slot(slot, &port_mngr->port_tbl[tbl_type], &iter, 0) {
			MTK_PORT_SEARCH_FROM_RADIX_TREE(port, slot);
			MTK_PORT_INTERNAL_NODE_CHECK(port, slot, iter);
			if (!strncmp(port->info.name, name, MTK_DFLT_PORT_NAME_LEN))
				return port;
		}
		tbl_type++;
	} while (tbl_type < PORT_TBL_MAX);

	return NULL;
}

static int mtk_port_tbl_create(struct mtk_port_mngr *port_mngr, struct mtk_port_cfg *cfg,
			       const int port_cnt, struct mtk_stale_list *s_list)
{
	struct mtk_port_cfg *dflt_port;
	struct mtk_port *port;
	int i;

	INIT_RADIX_TREE(&port_mngr->port_tbl[PORT_TBL_SAP], GFP_KERNEL);
	INIT_RADIX_TREE(&port_mngr->port_tbl[PORT_TBL_MD], GFP_KERNEL);

	mtk_port_restore_from_stale_list(port_mngr, s_list);

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

static void mtk_port_tbl_destroy(struct mtk_port_mngr *port_mngr, struct mtk_stale_list *s_list)
{
	struct radix_tree_iter iter;
	struct mtk_port *port;
	void __rcu **slot;
	int tbl_type;

	tbl_type = PORT_TBL_SAP;
	do {
		radix_tree_for_each_slot(slot, &port_mngr->port_tbl[tbl_type], &iter, 0) {
			port = radix_tree_deref_slot(slot);
			if (!port)
				continue;
			ports_ops[port->info.type]->disable(port);
		}

		while (radix_tree_gang_lookup(&port_mngr->port_tbl[tbl_type],
					      (void **)&port, 0, 1))
			mtk_port_free_or_backup(port_mngr, port, s_list);
	} while (++tbl_type < PORT_TBL_MAX);
}

static struct mtk_stale_list *mtk_port_stale_list_create(struct mtk_ctrl_blk *ctrl_blk)
{
	struct mtk_stale_list *s_list;

	s_list = kzalloc_obj(*s_list, GFP_KERNEL);
	if (!s_list)
		return NULL;

	memcpy(s_list->dev_str, ctrl_blk->mdev->dev_str, MTK_DEV_STR_LEN);
	s_list->dev_id = -1;
	INIT_LIST_HEAD(&s_list->ports);
	rwlock_init(&s_list->port_mngr_lock);

	mutex_lock(&port_mngr_grp_mtx);
	list_add_tail(&s_list->entry, &stale_list_grp);
	mutex_unlock(&port_mngr_grp_mtx);

	return s_list;
}

static void mtk_port_stale_list_destroy(struct mtk_stale_list *s_list)
{
	mutex_lock(&port_mngr_grp_mtx);
	list_del(&s_list->entry);
	mutex_unlock(&port_mngr_grp_mtx);
	kfree(s_list);
}

static struct mtk_stale_list *mtk_port_stale_list_search(const char *dev_str)
{
	struct mtk_stale_list *tmp, *s_list = NULL;

	mutex_lock(&port_mngr_grp_mtx);
	list_for_each_entry(tmp, &stale_list_grp, entry) {
		if (!strncmp(tmp->dev_str, dev_str, MTK_DEV_STR_LEN)) {
			s_list = tmp;
			break;
		}
	}
	mutex_unlock(&port_mngr_grp_mtx);

	return s_list;
}

void mtk_port_stale_list_grp_cleanup(void)
{
	struct mtk_stale_list *s_list, *next_s_list;
	struct mtk_port *port, *next_port;

	mutex_lock(&port_mngr_grp_mtx);
	list_for_each_entry_safe(s_list, next_s_list, &stale_list_grp, entry) {
		list_del(&s_list->entry);

		list_for_each_entry_safe(port, next_port, &s_list->ports, stale_entry) {
			clear_bit(PORT_S_ON_STALE_LIST, &port->status);
			kref_put(&port->kref, mtk_port_release);
		}

		if (s_list->dev_id >= 0)
			ida_free(&ccci_dev_ids, s_list->dev_id);
		kfree(s_list);
	}
	mutex_unlock(&port_mngr_grp_mtx);
}

static struct mtk_stale_list *mtk_port_stale_list_init(struct mtk_ctrl_blk *ctrl_blk, int *dev_id)
{
	struct mtk_stale_list *s_list;

	s_list = mtk_port_stale_list_search(ctrl_blk->mdev->dev_str);
	if (!s_list) {
		s_list = mtk_port_stale_list_create(ctrl_blk);
		if (unlikely(!s_list))
			return NULL;
	}

	mutex_lock(&port_mngr_grp_mtx);
	if (s_list->dev_id < 0) {
		*dev_id = ida_alloc_range(&ccci_dev_ids, 0, MTK_DFLT_MAX_DEV_CNT - 1, GFP_KERNEL);
	} else {
		*dev_id = s_list->dev_id;
		s_list->dev_id = -1;
	}
	mutex_unlock(&port_mngr_grp_mtx);

	return s_list;
}

static void mtk_port_stale_list_exit(struct mtk_ctrl_blk *ctrl_blk,
				     struct mtk_stale_list *s_list, int dev_id)
{
	if (!s_list)
		return;
	mutex_lock(&port_mngr_grp_mtx);
	if (list_empty(&s_list->ports)) {
		ida_free(&ccci_dev_ids, dev_id);
		mutex_unlock(&port_mngr_grp_mtx);
		mtk_port_stale_list_destroy(s_list);
	} else {
		s_list->dev_id = dev_id;
		mutex_unlock(&port_mngr_grp_mtx);
	}
}

void mtk_port_trb_init(struct mtk_port *port, struct trb *trb, enum mtk_trb_cmd_type cmd,
		       int (*trb_complete)(struct sk_buff *skb))
{
	kref_init(&trb->kref);
	trb->channel_id = port->info.rx_ch;
	trb->status = MTK_DFLT_TRB_STATUS;
	trb->priv = port;
	trb->cmd = cmd;
	trb->trb_complete = trb_complete;
}

void mtk_port_trb_free(struct kref *trb_kref)
{
	struct trb *trb = container_of(trb_kref, struct trb, kref);
	struct sk_buff *skb, *frag_skb, *next_skb;

	skb = container_of((char *)trb, struct sk_buff, cb[0]);
	/* Free frag_list for scatter gather TX */
	if (trb->cmd == TRB_CMD_TX && skb_has_frag_list(skb)) {
		frag_skb = skb_shinfo(skb)->frag_list;
		while (frag_skb) {
			next_skb = frag_skb->next;
			frag_skb->next = NULL;
			dev_kfree_skb_any(frag_skb);
			frag_skb = next_skb;
		}
		skb_shinfo(skb)->frag_list = NULL;
		skb->data_len = 0;
	}
	dev_kfree_skb_any(skb);
}
EXPORT_SYMBOL_GPL(mtk_port_trb_free);

static int mtk_port_open_trb_complete(struct sk_buff *skb)
{
	struct trb_open_priv *trb_open_priv = (struct trb_open_priv *)skb->data;
	struct trb *trb = (struct trb *)skb->cb;
	struct mtk_port *port = trb->priv;

	if (!trb->status) {
		port->tx_mtu = trb_open_priv->tx_mtu;
		port->rx_mtu = trb_open_priv->rx_mtu;
		port->tx_frag_size = trb_open_priv->tx_frag_size;
		port->rx_frag_size = trb_open_priv->rx_frag_size;
		port->tx_mtu -= MTK_CCCI_H_ELEN;
		port->rx_mtu -= MTK_CCCI_H_ELEN;
	}

	wake_up_all(&port->trb_wq);

	kref_put(&trb->kref, mtk_port_trb_free);
	return 0;
}

static int mtk_port_close_trb_complete(struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct mtk_port *port = trb->priv;

	wake_up_all(&port->trb_wq);
	wake_up_all(&port->rx_wq);
	kref_put(&trb->kref, mtk_port_trb_free);

	return 0;
}

static int mtk_port_tx_complete(struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct mtk_port *port = trb->priv;

	if (trb->status < 0)
		dev_warn(port->port_mngr->ctrl_blk->mdev->dev,
			 "Failed to send data: status:%d, port:%s\n",
			 trb->status, port->info.name);

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
	mtk_port_add_header(skb);
	ret = mtk_port_status_check(port);
	if (!ret)
		ret = port_mngr->ctrl_blk->ops->submit_skb(port_mngr->ctrl_blk->mdev,
							   skb, force_send);

	if (ret < 0) {
		kref_put(&trb->kref, mtk_port_trb_free); /* kref count 2->1 */
		kref_put(&trb->kref, mtk_port_trb_free); /* kref count 1->0 */
		port->tx_seq--;
		goto out;
	}

	if (!blocking) {
		kref_put(&trb->kref, mtk_port_trb_free);
		ret = len;
		goto out;
	}
start_wait:

	/* wait trb done, and no timeout in tx blocking mode */
	ret = wait_event_interruptible_timeout(port->trb_wq,
					       trb->status <= 0 ||
					       test_bit(PORT_S_FLUSH, &port->status) ||
					       !test_bit(PORT_S_WR, &port->status),
					       MTK_DFLT_TRB_TIMEOUT);
	if (!ret) {
		goto start_wait;
	} else if (ret == -ERESTARTSYS) {
		ret = -EINTR;
	} else if (ret > 0) {
		if (test_bit(PORT_S_FLUSH, &port->status))
			ret = len;
		else
			ret = (!trb->status) ? len : trb->status;
	}
	kref_put(&trb->kref, mtk_port_trb_free);

out:
	return ret;
}

static int mtk_port_check_rx_seq(struct mtk_port *port, struct mtk_ccci_header *ccci_h)
{
	u16 seq_num, assert_bit, channel;
	struct mtk_md_dev *mdev;

	seq_num = FIELD_GET(MTK_HDR_FLD_SEQ, le32_to_cpu(ccci_h->status));
	assert_bit = FIELD_GET(MTK_HDR_FLD_AST, le32_to_cpu(ccci_h->status));
	if (assert_bit && port->rx_seq &&
	    ((seq_num - port->rx_seq) & MTK_CHECK_RX_SEQ_MASK) != 1) {
		mdev = port->port_mngr->ctrl_blk->mdev;
		channel = FIELD_GET(MTK_HDR_FLD_CHN, le32_to_cpu(ccci_h->status));
		dev_warn(mdev->dev,
			 "<ch: %04x> seq num out-of-order %d->%d, len(%u)\n",
			 channel, seq_num, port->rx_seq,
			 le32_to_cpu(ccci_h->packet_len));

		port->rx_seq = seq_num;
		return -EPROTO;
	}

	return 0;
}

static int mtk_port_rx_dispatch_frag_skb(struct mtk_port *port, struct sk_buff *skb)
{
	struct sk_buff *frag_skb, *frag_next;
	int ret;

	frag_skb = skb_shinfo(skb)->frag_list;
	skb->len -= skb->data_len;
	skb->data_len = 0;
	skb_shinfo(skb)->frag_list = NULL;

	ret = ports_ops[port->info.type]->recv(port, skb);
	if (ret < 0) {
		skb_shinfo(skb)->frag_list = frag_skb;
		return ret;
	}

	while (frag_skb) {
		frag_next = frag_skb->next;
		if (!frag_skb->len) {
			frag_skb->next = NULL;
			dev_kfree_skb_any(frag_skb);
			frag_skb = frag_next;
			continue;
		}
		frag_skb->next = NULL;
		ret = ports_ops[port->info.type]->recv(port, frag_skb);
		if (ret < 0) {
			frag_skb->next = frag_next;
			while (frag_skb) {
				frag_next = frag_skb->next;
				frag_skb->next = NULL;
				dev_kfree_skb_any(frag_skb);
				frag_skb = frag_next;
			}
			return -EIO;
		}
		frag_skb = frag_next;
	}

	return 0;
}

static int mtk_port_rx_dispatch(struct sk_buff *skb, void *priv, bool force_recv)
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
		dev_warn(port_mngr->ctrl_blk->mdev->dev,
			 "Unsupported: skb length(%d) is less than ccci header\n",
			 skb->len);
		goto drop_data;
	}

	channel = FIELD_GET(MTK_HDR_FLD_CHN, le32_to_cpu(ccci_h->status));
	port = mtk_port_search_by_id(port_mngr, channel);
	if (unlikely(!port)) {
		dev_warn(port_mngr->ctrl_blk->mdev->dev,
			 "Failed to find port by channel:%d\n", channel);
		goto drop_data;
	}

	ret = mtk_port_check_rx_seq(port, ccci_h);
	if (unlikely(ret))
		goto drop_data;

	port->rx_seq = FIELD_GET(MTK_HDR_FLD_SEQ, le32_to_cpu(ccci_h->status));
	skb_pull(skb, sizeof(*ccci_h));

	/* Support scatter gather transmission */
	if (port->rx_mtu > port->rx_frag_size) {
		ret = mtk_port_rx_dispatch_frag_skb(port, skb);
		/* -EIO means partial data dispatch complete, does not goto drop flow */
		if (ret < 0 && ret != -EIO)
			goto drop_frag_skb;
	} else {
		ret = ports_ops[port->info.type]->recv(port, skb);
		if (ret < 0)
			goto drop_data;
	}

	return ret;

drop_frag_skb:
	{
		struct sk_buff *frag_skb, *tmp;

		frag_skb = skb_shinfo(skb)->frag_list;
		while (frag_skb) {
			tmp = frag_skb->next;
			frag_skb->next = NULL;
			dev_kfree_skb_any(frag_skb);
			frag_skb = tmp;
		}
		skb_shinfo(skb)->frag_list = NULL;
	}
drop_data:
	dev_kfree_skb_any(skb);
	return ret;
}

int mtk_port_add_header(struct sk_buff *skb)
{
	struct mtk_ccci_header *ccci_h;
	struct mtk_port *port;
	struct trb *trb;

	trb = (struct trb *)skb->cb;
	if (trb->status == MTK_TRB_HEADER_ADDED)
		return 0;

	port = trb->priv;
	if (!port)
		return -EINVAL;

	ccci_h = skb_push(skb, sizeof(*ccci_h));

	ccci_h->packet_header = cpu_to_le32(0);
	ccci_h->packet_len = cpu_to_le32(skb->len);
	ccci_h->ex_msg = cpu_to_le32(0);
	ccci_h->status = cpu_to_le32(FIELD_PREP(MTK_HDR_FLD_CHN, port->info.tx_ch) |
				     FIELD_PREP(MTK_HDR_FLD_SEQ, port->tx_seq++) |
				     FIELD_PREP(MTK_HDR_FLD_AST, 1));

	trb->status = MTK_TRB_HEADER_ADDED;

	return 0;
}

struct mtk_ccci_header *mtk_port_strip_header(struct sk_buff *skb)
{
	struct mtk_ccci_header *ccci_h;

	if (skb->len < sizeof(*ccci_h)) {
		pr_err("Invalid input value\n");
		return NULL;
	}

	ccci_h = (struct mtk_ccci_header *)skb->data;

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

	skb = __dev_alloc_skb(Q_MTU_3_5K, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	trb_open_priv = (struct trb_open_priv *)skb->data;
	trb_open_priv->rx_done = mtk_port_rx_dispatch;

	skb_put(skb, sizeof(struct trb_open_priv));
	trb = (struct trb *)skb->cb;
	mtk_port_trb_init(port, trb, TRB_CMD_ENABLE, mtk_port_open_trb_complete);
	kref_get(&trb->kref);

	ret = port_mngr->ctrl_blk->ops->submit_skb(port_mngr->ctrl_blk->mdev, skb, true);
	if (ret) {
		dev_err(port_mngr->ctrl_blk->mdev->dev,
			"Failed to submit trb for port(%s), ret=%d\n",
			port->info.name, ret);
		kref_put(&trb->kref, mtk_port_trb_free);
		kref_put(&trb->kref, mtk_port_trb_free);
		return ret;
	}

	ret = wait_event_timeout(port->trb_wq, trb->status <= 0,
				 MTK_DFLT_TRB_TIMEOUT);
	if (!ret)
		ret = -ETIMEDOUT;
	else
		ret = trb->status;

	kref_put(&trb->kref, mtk_port_trb_free);

	return ret;
}

int mtk_port_ch_disable(struct mtk_port *port)
{
	struct mtk_port_mngr *port_mngr = port->port_mngr;
	struct sk_buff *skb;
	struct trb *trb;
	int ret;

	skb = __dev_alloc_skb(Q_MTU_3_5K, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	trb = (struct trb *)skb->cb;
	mtk_port_trb_init(port, trb, TRB_CMD_DISABLE, mtk_port_close_trb_complete);
	kref_get(&trb->kref);

	ret = port_mngr->ctrl_blk->ops->submit_skb(port_mngr->ctrl_blk->mdev, skb, true);
	if (ret) {
		dev_warn(port_mngr->ctrl_blk->mdev->dev,
			 "Failed to submit trb for port(%s), ret=%d\n",
			 port->info.name, ret);
		kref_put(&trb->kref, mtk_port_trb_free);
		kref_put(&trb->kref, mtk_port_trb_free);
		return ret;
	}

	ret = wait_event_timeout(port->trb_wq, trb->status <= 0,
				 MTK_DFLT_TRB_TIMEOUT);
	if (!ret)
		ret = -ETIMEDOUT;
	else
		ret = trb->status;

	kref_put(&trb->kref, mtk_port_trb_free);

	return ret;
}

int mtk_port_mngr_init(struct mtk_ctrl_blk *ctrl_blk, struct mtk_port_cfg *port_cfg, int port_cnt)
{
	struct mtk_port_mngr *port_mngr;
	struct mtk_stale_list *s_list;
	int ret = -ENOMEM;
	int dev_id;

	s_list = mtk_port_stale_list_init(ctrl_blk, &dev_id);
	if (!s_list) {
		dev_err((ctrl_blk->mdev)->dev, "Failed to init mtk_stale_list\n");
		goto err_out;
	}

	port_mngr = devm_kzalloc(ctrl_blk->mdev->dev, sizeof(*port_mngr), GFP_KERNEL);
	if (unlikely(!port_mngr)) {
		dev_err((ctrl_blk->mdev)->dev, "Failed to alloc memory for port_mngr\n");
		goto err_exit_stale_list;
	}

	port_mngr->ctrl_blk = ctrl_blk;
	port_mngr->dev_id = dev_id;

	ret = mtk_port_tbl_create(port_mngr, port_cfg, port_cnt, s_list);
	if (unlikely(ret)) {
		dev_err((ctrl_blk->mdev)->dev, "Failed to create port_tbl\n");
		goto err_free_port_mngr;
	}

	ctrl_blk->port_mngr = port_mngr;

	return ret;

err_free_port_mngr:
	mtk_port_tbl_destroy(port_mngr, s_list);
err_exit_stale_list:
	mtk_port_stale_list_exit(ctrl_blk, s_list, dev_id);
err_out:
	return ret;
}

void mtk_port_mngr_exit(struct mtk_ctrl_blk *ctrl_blk)
{
	struct mtk_port_mngr *port_mngr = ctrl_blk->port_mngr;
	struct mtk_stale_list *s_list;
	int dev_id;

	s_list = mtk_port_stale_list_search(port_mngr->ctrl_blk->mdev->dev_str);
	dev_id = port_mngr->dev_id;

	mtk_port_tbl_destroy(port_mngr, s_list);

	ctrl_blk->port_mngr = NULL;
	mtk_port_stale_list_exit(ctrl_blk, s_list, dev_id);
}
