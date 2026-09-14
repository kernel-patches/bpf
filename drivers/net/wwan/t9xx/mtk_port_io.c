// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */
#include <linux/netdevice.h>

#include "mtk_port_io.h"

static int mtk_port_get_locked(struct mtk_port *port)
{
	int ret = 0;

	mutex_lock(&port_mngr_grp_mtx);
	if (!port) {
		mutex_unlock(&port_mngr_grp_mtx);
		pr_err("Port does not exist\n");
		return -ENODEV;
	}
	kref_get(&port->kref);
	mutex_unlock(&port_mngr_grp_mtx);

	return ret;
}

static void mtk_port_put_locked(struct mtk_port *port)
{
	mutex_lock(&port_mngr_grp_mtx);
	kref_put(&port->kref, mtk_port_release);
	mutex_unlock(&port_mngr_grp_mtx);
}

static void mtk_port_struct_init(struct mtk_port *port)
{
	port->tx_seq = 0;
	port->rx_seq = -1;
	clear_bit(PORT_S_ENABLE, &port->status);
	kref_init(&port->kref);
	skb_queue_head_init(&port->rx_skb_list);
	port->rx_buf_size = MTK_RX_BUF_SIZE;
	init_waitqueue_head(&port->trb_wq);
	init_waitqueue_head(&port->rx_wq);
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
		ports_ops[port->info.type]->disable(port);
}

static void mtk_port_reset(struct mtk_port *port)
{
	port->tx_seq = 0;
	port->rx_seq = -1;
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
	if (!test_and_clear_bit(PORT_S_ENABLE, &port->status))
		return;

	clear_bit(PORT_S_WR, &port->status);
	mtk_port_ch_disable(port);
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

	port = mtk_port_search_by_name(port_mngr, name);
	if (port && port->info.type != PORT_TYPE_INTERNAL) {
		port = NULL;
		goto out;
	}

	ret = mtk_port_get_locked(port);
	if (ret)
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

	if (!port || !skb) {
		if (skb)
			dev_kfree_skb_any(skb);
		pr_err_ratelimited("Internal write: invalid input\n");
		return -EINVAL;
	}
	return mtk_port_send_data(port, skb,
				  !!(port->info.flags & PORT_F_BLOCKING),
				  !!(port->info.flags &
				     (PORT_F_BLOCKING | PORT_F_FORCE_SEND)));
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

int mtk_port_io_init(void)
{
	return 0;
}

void mtk_port_io_exit(void)
{
}

static const struct port_ops port_internal_ops = {
	.init = mtk_port_internal_init,
	.exit = mtk_port_internal_exit,
	.reset = mtk_port_reset,
	.enable = mtk_port_internal_enable,
	.disable = mtk_port_internal_disable,
	.recv = mtk_port_internal_recv,
};

const struct port_ops *ports_ops[PORT_TYPE_MAX] = {
	&port_internal_ops,
};
