// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include <linux/device.h>
#include <linux/freezer.h>
#include <linux/hashtable.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/nospec.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "mtk_cldma.h"
#include "mtk_ctrl_plane.h"
#include "mtk_dev.h"
#include "mtk_pci.h"
#include "mtk_port.h"
#include "mtk_trans_ctrl.h"

static struct mtk_ctrl_info_desc mtk_ctrl_info_tbl[] = {
	{0x0900, &ctrl_info_name(m9xx)},
	{0x01CA, &ctrl_info_name(m9xx)},
	{0, NULL},
};

#define QUEUE_CHL_MASK	0xFFFF

static bool mtk_queue_list_is_full(struct mtk_ctrl_trans *trans, struct queue_info *que)
{
	return skb_queue_len_lockless(&trans->trans_list[que->hif_id].skb_list[que->txqno]) >=
	       SKB_LIST_MAX_LEN;
}

static bool mtk_ctrl_chs_is_busy_or_empty(struct trb_srv *srv)
{
	struct srv_que *srv_que;
	int i;

	for (i = 0; i < NR_CLDMA; i++) {
		list_for_each_entry(srv_que, &srv->srv_q_list[i], list) {
			struct sk_buff *skb;
			struct trb *trb;

			skb = skb_peek(&srv->trans->trans_list[i].skb_list[srv_que->qno]);
			if (!skb)
				continue;

			/* ENABLE and DISABLE are software-only and are queued at
			 * the head, so gating them on TX budget would make a queue
			 * that cannot drain impossible to close.
			 */
			trb = (struct trb *)skb->cb;
			if (trb->cmd != TRB_CMD_TX ||
			    mtk_cldma_get_tx_budget(srv->trans->dev, i, srv_que->qno))
				return false;
		}
	}

	return true;
}

static void mtk_ctrl_ch_flush(struct sk_buff_head *skb_list)
{
	struct sk_buff *skb;
	struct trb *trb;

	while (!skb_queue_empty(skb_list)) {
		skb = skb_dequeue(skb_list);
		trb = (struct trb *)skb->cb;
		trb->status = -EIO;
		trb->trb_complete(skb);
	}
}

static void mtk_ctrl_chs_flush(struct trb_srv *srv)
{
	struct srv_que *srv_que;
	int i;

	for (i = 0; i < NR_CLDMA; i++)
		list_for_each_entry(srv_que, &srv->srv_q_list[i], list)
			mtk_ctrl_ch_flush(&srv->trans->trans_list[i].skb_list[srv_que->qno]);
}

static int mtk_ch_status_check(struct mtk_ctrl_trans *trans, struct sk_buff *skb)
{
	struct trb *trb = (struct trb *)skb->cb;
	struct trb_open_priv *trb_open_priv;
	struct queue_info *que;
	int ret = 0;

	que = radix_tree_lookup(&trans->queue_tbl, trb->channel_id & QUEUE_CHL_MASK);

	switch (trb->cmd) {
	case TRB_CMD_ENABLE:
		trb_open_priv = (struct trb_open_priv *)skb->data;
		trb_open_priv->log_rg_offset = que->log_rg_offset;
		trans->usr_cnt[que->hif_id][que->txqno]++;
		if (trans->usr_cnt[que->hif_id][que->txqno] == 1)
			break;
		trb_open_priv->tx_mtu = que->tx_mtu;
		trb_open_priv->rx_mtu = que->rx_mtu;
		trb_open_priv->tx_frag_size = que->tx_frag_size;
		trb_open_priv->rx_frag_size = que->rx_frag_size;
		if (mtk_cldma_check_ch_cfg(trans->dev, que)) {
			trb->status = -EINVAL;
			ret = -EINVAL;
		} else {
			trb->status = -EBUSY;
			ret = -EBUSY;
		}
		trb->trb_complete(skb);
		break;
	case TRB_CMD_DISABLE:
		if (trans->usr_cnt[que->hif_id][que->txqno] > 0) {
			trans->usr_cnt[que->hif_id][que->txqno]--;
			if (!trans->usr_cnt[que->hif_id][que->txqno])
				break;
		}
		trb->status = -EBUSY;
		trb->trb_complete(skb);
		ret = -EBUSY;
		break;
	default:
		dev_err((trans->mdev)->dev, "Invalid trb command(%d)\n", trb->cmd);
		ret = -EINVAL;
		break;
	}
	return ret;
}

/* Single consumer per srv_que — only this kthread dequeues from skb_list.
 * The list lock is held around every list read (peek, is_last, peek_next,
 * unlink) so a producer inserting a DISABLE at the head cannot race the
 * traversal, but it is dropped across submit and dispatch: those paths
 * may allocate with GFP_KERNEL and thus sleep. Dropping the lock there
 * is safe because no other consumer can steal the peeked skb.
 */
static void mtk_ctrl_trb_handler(struct trb_srv *srv, struct trans_list *trans_list, u32 qno)
{
	struct sk_buff_head *skb_list = &trans_list->skb_list[qno];
	struct mtk_ctrl_trans *trans = srv->trans;
	struct sk_buff *skb, *skb_next;
	struct trb *trb, *trb_next;
	unsigned long flags;
	bool kick = false;
	int loop = 0;
	int err;

	do {
		spin_lock_irqsave(&skb_list->lock, flags);
		skb = skb_peek(skb_list);
		if (!skb) {
			spin_unlock_irqrestore(&skb_list->lock, flags);
			break;
		}
		trb = (struct trb *)skb->cb;
		kref_get(&trb->kref);

		switch (trb->cmd) {
		case TRB_CMD_ENABLE:
		case TRB_CMD_DISABLE:
			__skb_unlink(skb, skb_list);
			spin_unlock_irqrestore(&skb_list->lock, flags);
			err = mtk_ch_status_check(trans, skb);
			if (!err) {
				kick = true;
				if (trb->cmd == TRB_CMD_DISABLE)
					mtk_ctrl_ch_flush(skb_list);
			}
			break;
		case TRB_CMD_TX:
			spin_unlock_irqrestore(&skb_list->lock, flags);
			err = mtk_cldma_submit_tx(trans->dev, skb);
			if (err) {
				if (trans_list->tx_burst_cnt[qno]) {
					kick = true;
					break;
				}
				if (err == -EAGAIN) {
					kref_put(&trb->kref, mtk_port_trb_free);
					return;
				}

				skb_unlink(skb, skb_list);
				trb->status = err;
				trb->trb_complete(skb);
				break;
			}

			trans_list->tx_burst_cnt[qno]++;
			spin_lock_irqsave(&skb_list->lock, flags);
			if (trans_list->tx_burst_cnt[qno] >= TX_BURST_MAX_CNT ||
			    skb_queue_is_last(skb_list, skb)) {
				kick = true;
			} else {
				skb_next = skb_peek_next(skb, skb_list);
				trb_next = (struct trb *)skb_next->cb;
				if (trb_next->cmd != TRB_CMD_TX)
					kick = true;
			}

			__skb_unlink(skb, skb_list);
			spin_unlock_irqrestore(&skb_list->lock, flags);
			break;
		default:
			__skb_unlink(skb, skb_list);
			spin_unlock_irqrestore(&skb_list->lock, flags);
			trb->status = -EINVAL;
			trb->trb_complete(skb);
			break;
		}

		if (kick) {
			err = mtk_cldma_trb_process(trans->dev, skb);
			if (err)
				dev_err_ratelimited((trans->mdev)->dev,
						    "Failed to process trb on queue %u: %d\n",
						    qno, err);
			trans_list->tx_burst_cnt[qno] = 0;
			kick = false;
		}

		kref_put(&trb->kref, mtk_port_trb_free);

		loop++;
	} while (loop < TRB_NUM_PER_ROUND);
}

static void mtk_ctrl_trb_process(struct trb_srv *srv)
{
	struct mtk_ctrl_trans *trans = srv->trans;
	struct srv_que *srv_que;
	int i;

	for (i = 0; i < NR_CLDMA; i++)
		list_for_each_entry(srv_que, &srv->srv_q_list[i], list)
			mtk_ctrl_trb_handler(srv, &trans->trans_list[i], srv_que->qno);
}

static int mtk_ctrl_trb_thread(void *args)
{
	struct trb_srv *srv = args;

	for (;;) {
		wait_event_interruptible(srv->trb_waitq,
					 !mtk_ctrl_chs_is_busy_or_empty(srv) ||
					 kthread_should_stop() || kthread_should_park());
		if (kthread_should_stop())
			break;

		if (kthread_should_park())
			kthread_parkme();

		do {
			mtk_ctrl_trb_process(srv);
			cond_resched();
		} while (!mtk_ctrl_chs_is_busy_or_empty(srv) && !kthread_should_stop() &&
			 !kthread_should_park());
	}
	mtk_ctrl_chs_flush(srv);
	return 0;
}

static int mtk_ctrl_trb_srv_init(struct mtk_ctrl_trans *trans)
{
	struct srv_que *srv_que;
	struct trb_srv *srv;
	int i, j;
	int ret;

	for (i = 0; i < trans->trb_srv_num; i++) {
		srv = kzalloc_obj(*srv);
		if (!srv) {
			ret = -ENOMEM;
			goto err_free_srv;
		}

		srv->trans = trans;
		srv->srv_id = i;
		trans->trb_srv[i] = srv;

		init_waitqueue_head(&srv->trb_waitq);
		for (j = 0; j < NR_CLDMA; j++)
			INIT_LIST_HEAD(&srv->srv_q_list[j]);
	}

	for (i = 0; i < NR_CLDMA; i++)
		for (j = 0; j < HW_QUE_NUM; j++) {
			if (trans->srv_cfg[i][j] < 0 ||
			    trans->srv_cfg[i][j] >= trans->trb_srv_num)
				trans->srv_cfg[i][j] = 0;
			srv_que = kzalloc_obj(*srv_que);
			if (!srv_que) {
				ret = -ENOMEM;
				goto err_free_srv_que;
			}
			srv_que->hif_id = i;
			srv_que->qno = j;
			list_add_tail(&srv_que->list,
				      &trans->trb_srv[trans->srv_cfg[i][j]]->srv_q_list[i]);
		}

	for (i = 0; i < trans->trb_srv_num; i++) {
		trans->trb_srv[i]->trb_thread = kthread_run(mtk_ctrl_trb_thread, trans->trb_srv[i],
							    "mtk_trb_srv%d_%s", i,
							    trans->mdev->dev_str);
		if (IS_ERR(trans->trb_srv[i]->trb_thread)) {
			ret = PTR_ERR(trans->trb_srv[i]->trb_thread);
			trans->trb_srv[i]->trb_thread = NULL;
			goto err_stop_kthread;
		}
	}

	return 0;
err_stop_kthread:
	while (--i >= 0)
		kthread_stop(trans->trb_srv[i]->trb_thread);
err_free_srv_que:
	for (i = 0; i < trans->trb_srv_num; i++) {
		for (j = 0; j < NR_CLDMA; j++) {
			struct srv_que *next_srv_que;

			list_for_each_entry_safe(srv_que, next_srv_que,
						 &trans->trb_srv[i]->srv_q_list[j], list) {
				list_del(&srv_que->list);
				kfree(srv_que);
			}
		}
	}
err_free_srv:
	for (i = 0; i < trans->trb_srv_num; i++) {
		if (!trans->trb_srv[i])
			break;
		kfree(trans->trb_srv[i]);
		trans->trb_srv[i] = NULL;
	}

	return ret;
}

static void mtk_ctrl_trb_srv_exit(struct mtk_ctrl_trans *trans)
{
	struct srv_que *srv_que, *next_srv_que;
	struct trb_srv *srv;
	int i, j;

	for (i = 0; i < trans->trb_srv_num; i++) {
		srv = trans->trb_srv[i];
		if (!srv)
			continue;
		kthread_stop(srv->trb_thread);
		for (j = 0; j < NR_CLDMA; j++) {
			list_for_each_entry_safe(srv_que, next_srv_que,
						 &trans->trb_srv[i]->srv_q_list[j], list) {
				list_del(&srv_que->list);
				kfree(srv_que);
			}
		}
		kfree(srv);
		trans->trb_srv[i] = NULL;
	}
}

static void mtk_ctrl_remove_radix_tree(struct mtk_ctrl_trans *trans)
{
	struct radix_tree_iter iter;
	struct queue_info *queue;
	void __rcu **slot;

	radix_tree_for_each_slot(slot, &trans->queue_tbl, &iter, 0) {
		queue = radix_tree_deref_slot(slot);
		if (!queue)
			continue;
		radix_tree_delete(&trans->queue_tbl, iter.index);
		kfree(queue);
	}
}

static int mtk_pcie_hif_init(struct mtk_md_dev *mdev)
{
	struct mtk_ctrl_blk *ctrl_blk = mdev->ctrl_blk;
	struct queue_info *queue, *queue_info;
	struct mtk_ctrl_trans *trans;
	int i, j;
	int ret;

	trans = ctrl_blk->ctrl_hw_priv;
	trans->ctrl_blk = ctrl_blk;
	queue_info = trans->queue_info;

	INIT_RADIX_TREE(&trans->queue_tbl, GFP_KERNEL);
	for (i = 0; i < trans->queue_info_num; i++) {
		queue = kmemdup(queue_info + i, sizeof(*queue), GFP_KERNEL);
		if (!queue) {
			ret = -ENOMEM;
			goto err_free_radix_tree;
		}
		if (queue->txqno >= HW_QUE_NUM || queue->rxqno >= HW_QUE_NUM ||
		    queue->hif_id >= NR_CLDMA) {
			dev_err(mdev->dev, "Failed to get correct queue info %x\n",
				queue->rx_chl);
			kfree(queue);
			ret = -EINVAL;
			goto err_free_radix_tree;
		}
		ret = radix_tree_insert(&trans->queue_tbl, queue->rx_chl & QUEUE_CHL_MASK, queue);
		if (ret) {
			dev_err(mdev->dev, "Insert %x fail, ret: %d", queue->rx_chl, ret);
			kfree(queue);
			goto err_free_radix_tree;
		}
	}

	for (i = 0; i < NR_CLDMA; i++) {
		for (j = 0; j < HW_QUE_NUM; j++) {
			skb_queue_head_init(&trans->trans_list[i].skb_list[j]);
			trans->trans_list[i].tx_burst_cnt[j] = 0;
			/* usr_cnt tracks the queues rebuilt by mtk_cldma_init()
			 * below, so it must be reset with them. Otherwise a
			 * count left over from a torn-down cycle makes the
			 * channel permanently unopenable.
			 */
			trans->usr_cnt[i][j] = 0;
		}
	}
	ret = mtk_cldma_init(trans);
	if (ret)
		goto err_free_radix_tree;

	ret = mtk_ctrl_trb_srv_init(trans);
	if (ret)
		goto err_cldma_exit;

	atomic_set(&trans->available, 1);

	return 0;

err_cldma_exit:
	mtk_cldma_exit(trans);
err_free_radix_tree:
	mtk_ctrl_remove_radix_tree(trans);

	return ret;
}

static int mtk_pcie_hif_exit(struct mtk_md_dev *mdev)
{
	struct mtk_ctrl_blk *ctrl_blk = mdev->ctrl_blk;
	struct mtk_ctrl_trans *trans;

	trans = ctrl_blk->ctrl_hw_priv;

	/* Hold submit_lock across the whole teardown: late submitters either
	 * see available and finish before the teardown starts, or block here
	 * and then bail out on !available. Also makes this exit idempotent,
	 * so both the FSM listener and device removal may call it.
	 */
	mutex_lock(&trans->submit_lock);
	if (!atomic_read(&trans->available)) {
		mutex_unlock(&trans->submit_lock);
		return 0;
	}
	atomic_set(&trans->available, 0);
	mtk_cldma_exit(trans);
	mtk_ctrl_trb_srv_exit(trans);
	mtk_ctrl_remove_radix_tree(trans);
	mutex_unlock(&trans->submit_lock);

	return 0;
}

static int mtk_pcie_hif_submit_skb(struct mtk_md_dev *mdev, struct sk_buff *skb, bool force_send)
{
	struct mtk_ctrl_blk *ctrl_blk = mdev->ctrl_blk;
	struct mtk_ctrl_trans *trans;
	struct queue_info *que;
	struct trb *trb;
	int ret;

	trans = ctrl_blk->ctrl_hw_priv;
	trb = (struct trb *)skb->cb;

	if (trb->cmd == TRB_CMD_STOP || trb->cmd == TRB_CMD_RECOVER) {
		trb->trb_complete(skb);
		return 0;
	}

	mutex_lock(&trans->submit_lock);

	if (!atomic_read(&trans->available)) {
		ret = -EIO;
		goto unlock;
	}

	que = radix_tree_lookup(&trans->queue_tbl, trb->channel_id & QUEUE_CHL_MASK);
	if (!que) {
		dev_warn(mdev->dev, "lookup que fail, ch_id: %x\n",
			 trb->channel_id);
		ret = -EINVAL;
		goto unlock;
	}

	if (mtk_queue_list_is_full(trans, que) && !force_send) {
		ret = -EAGAIN;
		goto unlock;
	}

	if (trb->cmd == TRB_CMD_DISABLE) {
		struct sk_buff *entry = NULL;
		struct sk_buff_head *list;
		struct sk_buff *iter;
		unsigned long flags;

		/* A disable may overtake queued data, so teardown does not
		 * wait for a TX backlog, but it must never overtake a pending
		 * ENABLE for the same queue: the two do not commute, and a
		 * DISABLE consumed before its ENABLE closes nothing while the
		 * ENABLE then arms rings nobody owns.
		 */
		list = &trans->trans_list[que->hif_id].skb_list[que->txqno];
		spin_lock_irqsave(&list->lock, flags);
		skb_queue_walk(list, iter) {
			if (((struct trb *)iter->cb)->cmd != TRB_CMD_ENABLE) {
				entry = iter;
				break;
			}
		}
		if (entry)
			__skb_queue_before(list, entry, skb);
		else
			__skb_queue_tail(list, skb);
		spin_unlock_irqrestore(&list->lock, flags);
	} else {
		skb_queue_tail(&trans->trans_list[que->hif_id].skb_list[que->txqno], skb);
	}

	wake_up(&trans->trb_srv[trans->srv_cfg[que->hif_id][que->txqno]]->trb_waitq);
	ret = 0;

unlock:
	mutex_unlock(&trans->submit_lock);
	return ret;
}

static void mtk_pcie_hif_fsm_indication(struct mtk_md_dev *mdev, struct mtk_fsm_param *param)
{
	struct mtk_ctrl_blk *ctrl_blk = mdev->ctrl_blk;
	struct mtk_ctrl_trans *trans;

	trans = ctrl_blk->ctrl_hw_priv;
	mtk_cldma_fsm_state_listener(param, trans);
}

static int mtk_pcie_hif_cmd_func(struct mtk_md_dev *mdev, int cmd, void *data)
{
	struct mtk_ctrl_blk *ctrl_blk = mdev->ctrl_blk;
	struct mtk_ctrl_trans *trans;
	struct queue_info *que;
	int ret;

	switch (cmd) {
	case HIF_CTRL_CMD_CHECK_TX_FULL:
		trans = ctrl_blk->ctrl_hw_priv;
		mutex_lock(&trans->submit_lock);
		if (!atomic_read(&trans->available)) {
			ret = -EIO;
			break;
		}
		que = radix_tree_lookup(&trans->queue_tbl,
					((union ctrl_hif_cmd_data *)data)->rx_ch & QUEUE_CHL_MASK);
		if (!que) {
			dev_warn(mdev->dev, "Failed to find que to check tx full\n");
			ret = -EINVAL;
			break;
		}
		ret = mtk_queue_list_is_full(trans, que);
		break;
	default:
		return -EINVAL;
	}
	mutex_unlock(&trans->submit_lock);

	return ret;
}

static struct mtk_ctrl_hif_ops pcie_ctrl_ops = {
	.init = mtk_pcie_hif_init,
	.exit = mtk_pcie_hif_exit,
	.submit_skb = mtk_pcie_hif_submit_skb,
	.fsm_indication = mtk_pcie_hif_fsm_indication,
	.send_cmd = mtk_pcie_hif_cmd_func,
};

static void mtk_trans_get_ctrl_info(struct mtk_ctrl_cfg *cfg,
				    struct mtk_ctrl_trans *trans, u32 hw_ver)
{
	struct mtk_ctrl_info_desc *ctrl_info_desc;
	struct mtk_ctrl_info *ctrl_info;
	u8 i;

	for (i = 0; (ctrl_info_desc = &mtk_ctrl_info_tbl[i]) && ctrl_info_desc &&
	     ctrl_info_desc->ctrl_info; i++) {
		if (ctrl_info_desc->hw_ver != hw_ver)
			continue;

		ctrl_info = ctrl_info_desc->ctrl_info;
		cfg->port_layer_cfg = ctrl_info->ctrl_cfg->port_layer_cfg;
		memcpy(trans->srv_cfg, ctrl_info->srv_cfg,
		       sizeof(int) * NR_CLDMA * HW_QUE_NUM);
		trans->queue_info = ctrl_info->queue_info;
		trans->queue_info_num = ctrl_info->queue_info_num;
		trans->trb_srv_num = ctrl_info->trb_srv_num;
	}
}

int mtk_trans_ctrl_init(struct mtk_md_dev *mdev)
{
	struct mtk_ctrl_trans *trans;
	struct mtk_ctrl_blk *ctrl_blk;
	struct mtk_ctrl_cfg *cfg;
	int err;

	trans = devm_kzalloc(mdev->dev, sizeof(*trans), GFP_KERNEL);
	if (!trans)
		return -ENOMEM;
	trans->mdev = mdev;
	mutex_init(&trans->submit_lock);
	atomic_set(&trans->available, 0);

	cfg = devm_kzalloc(mdev->dev, sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return -ENOMEM;

	mtk_trans_get_ctrl_info(cfg, trans, mdev->hw_ver);
	if (!cfg->port_layer_cfg || !trans->queue_info ||
	    trans->trb_srv_num <= 0 || trans->trb_srv_num > TRB_SRV_MAX_NUM ||
	    trans->queue_info_num <= 0) {
		dev_err(mdev->dev, "Failed to get ctrl info!\n");
		return -EINVAL;
	}

	err = mtk_ctrl_init(mdev, &pcie_ctrl_ops, cfg);
	if (err)
		return err;

	ctrl_blk = mdev->ctrl_blk;
	ctrl_blk->ctrl_hw_priv = trans;

	return 0;
}

int mtk_trans_ctrl_exit(struct mtk_md_dev *mdev)
{
	/* FSM_STATE_OFF normally tears the HIF down. If that never ran, the
	 * trb kthreads and the CLDMA irq callback would outlive the devm
	 * allocations they point at, so do it here. mtk_pcie_hif_exit() is
	 * idempotent under trans->submit_lock, so calling it again is safe.
	 */
	mtk_pcie_hif_exit(mdev);

	mtk_ctrl_exit(mdev);

	return 0;
}
