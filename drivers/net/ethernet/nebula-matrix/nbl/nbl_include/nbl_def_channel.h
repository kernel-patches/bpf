/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_CHANNEL_H_
#define _NBL_DEF_CHANNEL_H_

#include <linux/types.h>

struct nbl_channel_mgt;
struct nbl_adapter;

typedef void (*nbl_chan_resp)(void *, u16, u16, void *, u32);

/*
 * Mailbox wire opcodes, stable wire ABI shared between driver and firmware.
 * Each opcode has a fixed assigned number to preserve compatibility.
 * ABI compatibility rules:
 * 1. New opcodes shall only be appended before NBL_CHAN_MSG_MAILBOX_MAX;
 * 2. Reordering, inserting or deleting existing enumerators breaks driver-
 *    firmware interoperability and must be avoided;
 * 3. Modifications to existing opcodes require synchronized firmware ABI
 *    updates.
 *
 * Only opcodes currently used by in-tree driver logic are defined here.
 * Unimplemented feature opcodes (KTLS, IPsec, vDPA, mirror etc.) will be
 * added incrementally together with their corresponding driver
 * implementation patches.
 */
enum nbl_chan_msg_type {
	NBL_CHAN_MSG_ACK = 0,
	/* mailbox msg end */
	NBL_CHAN_MSG_MAILBOX_MAX,
};

enum nbl_chan_state {
	NBL_CHAN_IRQ_RDY,
	NBL_CHAN_STATE_NBITS
};

struct nbl_chan_send_info {
	void *arg;
	size_t arg_len;
	void *resp;
	size_t resp_len;
	u16 dstid;
	u16 msg_type;
	u16 ack;
	u16 ack_len;
};

struct nbl_chan_ack_info {
	void *data;
	int err;
	u32 data_len;
	u16 dstid;
	u16 msg_type;
	u16 msgid;
};

enum nbl_channel_type {
	NBL_CHAN_TYPE_MAILBOX,
	NBL_CHAN_TYPE_MAX
};

static inline void
nbl_chan_fill_send_info(struct nbl_chan_send_info *info,
			u16 dst_id, u16 msg_type,
			void *argument, u32 arg_length,
			void *response, u32 resp_length,
			bool need_ack)
{
	info->dstid = dst_id;
	info->msg_type = msg_type;
	info->arg = argument;
	info->arg_len = arg_length;
	info->resp = response;
	info->resp_len = resp_length;
	info->ack = need_ack;
}

static inline void
nbl_chan_fill_ack_info(struct nbl_chan_ack_info *info,
		       u16 dst_id, u16 msg_type, u16 msg_id,
		       int err_code, void *ack_data, u32 data_length)
{
	info->dstid = dst_id;
	info->msg_type = msg_type;
	info->msgid = msg_id;
	info->err = err_code;
	info->data = ack_data;
	info->data_len = data_length;
}

struct nbl_channel_ops {
	int (*send_msg)(struct nbl_channel_mgt *chan_mgt,
			struct nbl_chan_send_info *chan_send);
	int (*send_ack)(struct nbl_channel_mgt *chan_mgt,
			struct nbl_chan_ack_info *chan_ack);
	int (*register_msg)(struct nbl_channel_mgt *chan_mgt, u16 msg_type,
			    nbl_chan_resp func, void *callback_priv);
	void (*unregister_all_msg)(struct nbl_channel_mgt *chan_mgt);
	void (*cfg_chan_qinfo_map_table)(struct nbl_channel_mgt *chan_mgt,
					 u8 bus, u8 devid);
	bool (*check_queue_exist)(struct nbl_channel_mgt *chan_mgt,
				  u8 chan_type);
	int (*setup_queue)(struct nbl_channel_mgt *chan_mgt, u8 chan_type);
	int (*teardown_queue)(struct nbl_channel_mgt *chan_mgt, u8 chan_type);
	void (*clean_queue_subtask)(struct nbl_channel_mgt *chan_mgt,
				    u8 chan_type);
	void (*register_chan_task)(struct nbl_channel_mgt *chan_mgt,
				   u8 chan_type, struct work_struct *task);
	void (*set_queue_state)(struct nbl_channel_mgt *chan_mgt,
				enum nbl_chan_state state, u8 chan_type,
				u8 set);
};

struct nbl_channel_ops_tbl {
	struct nbl_channel_ops *ops;
	struct nbl_channel_mgt *priv;
};

int nbl_chan_init_common(struct nbl_adapter *adapter);
void nbl_chan_remove_common(struct nbl_adapter *adapter);
#endif
