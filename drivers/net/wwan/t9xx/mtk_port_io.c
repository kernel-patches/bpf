// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */
#include <linux/netdevice.h>

#include "mtk_port_io.h"

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
	init_waitqueue_head(&port->trb_wq);
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

	if (test_and_set_bit(PORT_S_ENABLE, &port->status))
		return;

	ret = mtk_port_ch_enable(port);
	if (ret && ret != -EBUSY) {
		/* On -ETIMEDOUT the ENABLE trb may still be queued; queue a
		 * DISABLE behind it so the channel does not end up armed with
		 * no software owner.
		 */
		mtk_port_ch_disable(port);
		clear_bit(PORT_S_ENABLE, &port->status);
		return;
	}

	set_bit(PORT_S_WR, &port->status);
}

static void mtk_port_internal_disable(struct mtk_port *port)
{
	int ret;

	if (!test_and_clear_bit(PORT_S_ENABLE, &port->status))
		return;

	/* PORT_S_WR is in the blocking TX wait condition: wake the waiters. */
	clear_bit(PORT_S_WR, &port->status);
	wake_up_all(&port->trb_wq);

	/* Failure must not abort teardown or keep PORT_S_ENABLE set:
	 * usr_cnt and the queues are rebuilt together by the next
	 * mtk_pcie_hif_init(), and a port left with the bit set could never
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
	int (*recv_cb)(void *priv, struct sk_buff *skb);
	struct mtk_internal_port *priv;
	int ret = -ENXIO;

	if (!test_bit(PORT_S_OPEN, &port->status))
		goto drop_data;

	priv = &port->i_priv;
	/* Pairs with the smp_store_release() in mtk_port_internal_recv_register(). */
	recv_cb = smp_load_acquire(&priv->recv_cb);
	if (!recv_cb || !priv->arg)
		goto drop_data;

	ret = recv_cb(priv->arg, skb);
	return ret;

drop_data:
	return ret;
}

static int mtk_port_common_open(struct mtk_port *port)
{
	int ret = 0;

	if (!test_bit(PORT_S_ENABLE, &port->status))
		return -ENODEV;

	if (test_and_set_bit(PORT_S_OPEN, &port->status))
		return -EBUSY;

	clear_bit(PORT_S_FLUSH, &port->status);

	return ret;
}

static void mtk_port_common_close(struct mtk_port *port)
{
	clear_bit(PORT_S_OPEN, &port->status);

	set_bit(PORT_S_FLUSH, &port->status);
	wake_up_all(&port->trb_wq);
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

	if (!test_and_clear_bit(PORT_S_OPEN, &port->status)) {
		pr_err("Port(%s) has been closed\n", port->info.name);
		ret = -EBADF;
		goto end;
	}

	mtk_port_common_close(port);
	mtk_port_put_locked(port);
end:
	return ret;
}

/* Consumes @skb, on failure too. */
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

/* @cb and @arg must stay valid until the receive path has been drained:
 * closing the port does not unregister them or wait for a callback that is
 * already running, so close alone does not make freeing @arg safe.
 * @cb owns the skb when it returns 0 or more; on a negative return the
 * caller frees it, so @cb must not.
 */
void mtk_port_internal_recv_register(void *i_port,
				     int (*cb)(void *priv, struct sk_buff *skb),
				     void *arg)
{
	struct mtk_port *port = i_port;
	struct mtk_internal_port *priv;

	priv = &port->i_priv;
	priv->arg = arg;
	/* Pairs with the smp_load_acquire() in mtk_port_internal_recv(). */
	smp_store_release(&priv->recv_cb, cb);
}

static const struct mtk_port_ops port_internal_ops = {
	.init = mtk_port_internal_init,
	.exit = mtk_port_internal_exit,
	.enable = mtk_port_internal_enable,
	.disable = mtk_port_internal_disable,
	.recv = mtk_port_internal_recv,
};

static const struct mtk_port_ops *mtk_port_ops_tbl[PORT_TYPE_MAX] = {
	&port_internal_ops,
};

const struct mtk_port_ops *mtk_port_get_ops(enum mtk_port_type type)
{
	return mtk_port_ops_tbl[type];
}
