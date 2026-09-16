/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_CHANNEL_H_
#define _NBL_CHANNEL_H_

#include <linux/types.h>

#include "../nbl_include/nbl_include.h"
#include "../nbl_include/nbl_def_channel.h"
#include "../nbl_include/nbl_def_hw.h"
#include "../nbl_include/nbl_def_common.h"
#include "../nbl_core.h"

#define NBL_CHAN_TX_RING_TO_DESC(tx_ring, i) \
	(&((((tx_ring)->desc.tx_desc))[i]))
#define NBL_CHAN_RX_RING_TO_DESC(rx_ring, i) \
	(&((((rx_ring)->desc.rx_desc))[i]))
#define NBL_CHAN_TX_RING_TO_BUF(tx_ring, i) (&(((tx_ring)->buf)[i]))
#define NBL_CHAN_RX_RING_TO_BUF(rx_ring, i) (&(((rx_ring)->buf)[i]))

#define NBL_CHAN_TX_WAIT_US			100
#define NBL_CHAN_TX_WAIT_US_MAX			120
#define NBL_CHAN_TX_WAIT_TIMES			100
#define NBL_CHAN_TX_WAIT_ACK_US_MIN		1000
#define NBL_CHAN_TX_WAIT_ACK_US_MAX		1200
#define NBL_CHAN_TX_WAIT_ACK_TIMES		5000
#define NBL_CHAN_QUEUE_LEN			256
#define NBL_CHAN_BUF_LEN			4096
#define NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN	16

#define NBL_CHAN_TX_DESC_AVAIL			0
#define NBL_CHAN_TX_DESC_USED			1
#define NBL_CHAN_RX_DESC_WRITE			1
#define NBL_CHAN_RX_DESC_AVAIL			3
#define NBL_CHAN_RX_DESC_USED			4

#define NBL_CHAN_ACK_HEAD_LEN			3
#define NBL_CHAN_ACK_RET_POS			2
#define NBL_CHAN_MSG_ID_POS			1
#define NBL_CHAN_MSG_TYPE_POS			0

#define NBL_CHAN_ACK_WAIT_TIME			(3 * HZ)
#define NBL_CHAN_RX_CLEAN_BUDGET		64
#define NBL_CHAN_HANDLER_TBL_BUCKET_SIZE	512

enum {
	NBL_MB_RX_QID = 0,
	NBL_MB_TX_QID = 1,
};

enum {
	NBL_MBX_STATUS_IDLE = 0,
	NBL_MBX_STATUS_WAITING,
	NBL_MBX_STATUS_ACKD,
	NBL_MBX_STATUS_TIMEOUT,
};

struct nbl_chan_tx_param {
	enum nbl_chan_msg_type msg_type;
	void *arg;
	size_t arg_len;
	u16 dstid;
	u16 msgid;
};

struct nbl_chan_buf {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct nbl_chan_tx_desc {
	__le16 flags;
	__le16 srcid;
	__le16 dstid;
	__le16 data_len;
	__le16 buf_len;
	__le64 buf_addr;
	__le16 msg_type;
	u8 data[NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN];
	__le16 msgid;
	u8 rsv[26];
} __packed;

struct nbl_chan_rx_desc {
	__le16 flags;
	__le32 buf_len;
	__le16 buf_id;
	__le64 buf_addr;
} __packed;

union nbl_chan_desc_ptr {
	struct nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_rx_desc *rx_desc;
};

struct nbl_chan_ring {
	union nbl_chan_desc_ptr desc;
	struct nbl_chan_buf *buf;
	u16 next_to_use;
	u16 tail_ptr; /* hardware does modulo ring size internally */
	u16 next_to_clean;
	dma_addr_t dma;
};

#define NBL_CHAN_MSG_INDEX_MAX 63

#define NBL_CHAN_MSGID_INDEX_MASK GENMASK(5, 0)
#define NBL_CHAN_MSGID_LOC_MASK GENMASK(13, 6)

static inline void nbl_chan_update_tail_ptr(struct nbl_hw_ops *hw_ops,
					    void *hw_priv, u32 tail_ptr, u8 qid)
{
	hw_ops->update_mailbox_queue_tail_ptr(hw_priv, tail_ptr, qid);
}

struct nbl_chan_waitqueue_head {
	struct wait_queue_head wait_queue;
	char *ack_data;
	int acked;
	s32 ack_err;
	u16 ack_data_len;
	u16 msg_type;
	int status;
	u8 msg_index;
	u16 dstid;
};

struct nbl_chan_info {
	wait_queue_head_t inflight_wait;
	struct nbl_chan_ring txq;
	struct nbl_chan_ring rxq;
	struct nbl_chan_waitqueue_head *wait;
	/*
	 *Protects access to the TX queue (txq) and related metadata.
	 *This mutex ensures exclusive access when updating the TX queue
	 */
	struct mutex txq_lock;
	/* Guards channel state bitmap, active and shutdn flags */
	struct mutex state_lock;
	/* Guards pending requests and pending work list operations */
	struct mutex pending_lock;
	struct work_struct *clean_task;
	u16 wait_head_index;
	u16 num_txq_entries;
	u16 num_rxq_entries;
	u16 txq_buf_size;
	u16 rxq_buf_size;
	DECLARE_BITMAP(state, NBL_CHAN_STATE_NBITS);
	u8 chan_type;
	atomic_t inflight_tx_cnt;
	bool shutdn;
	bool active;
};

struct nbl_chan_msg_node_data {
	nbl_chan_resp func;
	void *priv;
};

struct nbl_channel_mgt {
	struct nbl_common_info *common;
	struct nbl_hw_ops_tbl *hw_ops_tbl;
	struct nbl_chan_info *chan_info[NBL_CHAN_TYPE_MAX];
	struct nbl_hash_tbl_mgt *handle_hash_tbl;
};

#endif
