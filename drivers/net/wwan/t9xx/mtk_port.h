/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_PORT_H__
#define __MTK_PORT_H__

#include <linux/bits.h>
#include <linux/device.h>
#include <linux/radix-tree.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "mtk_ctrl_plane.h"
#include "mtk_dev.h"

#define MTK_PEER_ID_MASK			(0xF000)
#define MTK_PEER_ID_SHIFT			(12)
#define MTK_PEER_ID(ch)				(((ch) & MTK_PEER_ID_MASK) >> MTK_PEER_ID_SHIFT)
#define MTK_PEER_ID_SAP				(0x1)
#define MTK_PEER_ID_MD				(0x2)
#define MTK_CH_ID_MASK				(0x0FFF)
#define MTK_CH_ID(ch)				((ch) & MTK_CH_ID_MASK)
#define MTK_DFLT_MAX_DEV_CNT			(10)
#define MTK_DFLT_PORT_NAME_LEN			(20)

/* Mapping MTK_PEER_ID and mtk_port_tbl index */
#define MTK_PORT_TBL_TYPE(ch)			(MTK_PEER_ID(ch) - 1)

/* ccci header length + reserved space that is used in exception flow */
#define MTK_CCCI_H_ELEN		(128)

#define MTK_HDR_FLD_AST		((u32)BIT(31))
#define MTK_HDR_FLD_SEQ		GENMASK(30, 16)
#define MTK_HDR_FLD_CHN		GENMASK(15, 0)

#define MTK_INFO_FLD_EN		((u16)BIT(15))
#define MTK_INFO_FLD_CHID	GENMASK(14, 0)

enum mtk_port_status {
	PORT_S_DFLT = 0,
	PORT_S_ENABLE,
	PORT_S_OPEN,
	PORT_S_RD,
	PORT_S_WR,
	PORT_S_FLUSH,
	PORT_S_ON_STALE_LIST,
	PORT_S_STOP,
};

enum mtk_port_flag {
	PORT_F_DFLT = 0,
	PORT_F_BLOCKING = BIT(1),
	PORT_F_ALLOW_DROP = BIT(2),
	PORT_F_FORCE_SEND = BIT(6),
};

enum mtk_port_tbl {
	PORT_TBL_SAP,
	PORT_TBL_MD,
	PORT_TBL_MAX
};

enum mtk_port_type {
	PORT_TYPE_INTERNAL,
	PORT_TYPE_MAX
};

struct mtk_internal_port {
	void *arg;
	int (*recv_cb)(void *arg, struct sk_buff *skb);
};

struct mtk_port_cfg {
	enum mtk_ccci_ch tx_ch;
	enum mtk_ccci_ch rx_ch;
	enum mtk_port_type type;
	char name[MTK_DFLT_PORT_NAME_LEN];
	unsigned char flags;
};

struct mtk_port {
	struct mtk_port_cfg info;
	struct kref kref;
	bool enable;
	unsigned long status;
	unsigned int minor;
	unsigned short tx_seq;
	unsigned short rx_seq;
	unsigned int tx_mtu;
	unsigned int rx_mtu;
	u32 tx_frag_size;
	u32 rx_frag_size;
	struct sk_buff_head rx_skb_list;
	unsigned int rx_data_len;
	unsigned int rx_buf_size;
	wait_queue_head_t trb_wq;
	wait_queue_head_t rx_wq;
	struct list_head stale_entry;
	char dev_str[MTK_DEV_STR_LEN];
	struct mtk_port_mngr *port_mngr;
	struct mtk_internal_port i_priv;
};

struct mtk_port_mngr {
	struct mtk_ctrl_blk *ctrl_blk;
	struct radix_tree_root port_tbl[PORT_TBL_MAX];
	unsigned int port_cnt;
	int dev_id;
};

struct mtk_stale_list {
	struct list_head entry;
	struct list_head ports;
	char dev_str[MTK_DEV_STR_LEN];
	int dev_id;
	rwlock_t port_mngr_lock;
};

struct mtk_ccci_header {
	__le32 packet_header;
	__le32 packet_len;
	__le32 status;
	__le32 ex_msg;
};

struct mtk_port_layer_cfg {
	struct mtk_port_cfg *port_cfg;
	int port_cnt;
};

extern const struct port_ops *ports_ops[PORT_TYPE_MAX];

void mtk_port_release(struct kref *port_kref);
void mtk_port_trb_free(struct kref *trb_kref);
struct mtk_port *mtk_port_search_by_name(struct mtk_port_mngr *port_mngr, char *name);
void mtk_port_stale_list_grp_cleanup(void);
int mtk_port_add_header(struct sk_buff *skb);
struct mtk_ccci_header *mtk_port_strip_header(struct sk_buff *skb);
int mtk_port_status_check(struct mtk_port *port);
int mtk_port_send_data(struct mtk_port *port, void *data, bool blocking, bool force_send);
int mtk_port_status_update(struct mtk_md_dev *mdev, void *data, u32 data_len);
int mtk_port_ch_enable(struct mtk_port *port);
int mtk_port_ch_disable(struct mtk_port *port);
int mtk_port_mngr_init(struct mtk_ctrl_blk *ctrl_blk, struct mtk_port_cfg *port_cfg, int port_cnt);
void mtk_port_mngr_exit(struct mtk_ctrl_blk *ctrl_blk);
void mtk_port_trb_init(struct mtk_port *port, struct trb *trb, enum mtk_trb_cmd_type cmd,
		       int (*trb_complete)(struct sk_buff *skb));
#endif /* __MTK_PORT_H__ */
