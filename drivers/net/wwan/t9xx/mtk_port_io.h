/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_PORT_IO_H__
#define __MTK_PORT_IO_H__

#include <linux/skbuff.h>

#include "mtk_port.h"

#define MTK_RX_BUF_SIZE			(1024 * 1024)

extern struct mutex mtk_port_mngr_grp_mtx;

struct mtk_port_ops {
	int (*init)(struct mtk_port *port);
	void (*exit)(struct mtk_port *port);
	void (*enable)(struct mtk_port *port);
	void (*disable)(struct mtk_port *port);
	int (*recv)(struct mtk_port *port, struct sk_buff *skb);
};

const struct mtk_port_ops *mtk_port_get_ops(enum mtk_port_type type);

void *mtk_port_internal_open(struct mtk_md_dev *mdev, char *name, int flag);
int mtk_port_internal_close(void *i_port);
int mtk_port_internal_write(void *i_port, struct sk_buff *skb);
void mtk_port_internal_recv_register(void *i_port,
				     int (*cb)(void *priv, struct sk_buff *skb),
				     void *arg);

#endif /* __MTK_PORT_IO_H__ */
