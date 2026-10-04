/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2025 Cisco Systems, Inc.  All rights reserved. */

#ifndef _ENIC_MBOX_H_
#define _ENIC_MBOX_H_

#include <linux/bits.h>
#include <linux/if_ether.h>
#include <linux/types.h>

/*
 * Mailbox protocol for PF-VF communication over the admin channel.
 *
 * Even numbers are requests, odd numbers are replies/acks.
 * The prefix indicates the initiator: VF_ = VF-initiated, PF_ = PF-initiated.
 */
enum enic_mbox_msg_type {
	ENIC_MBOX_VF_CAPABILITY_REQUEST		= 0,
	ENIC_MBOX_VF_CAPABILITY_REPLY		= 1,
	ENIC_MBOX_VF_REGISTER_REQUEST		= 2,
	ENIC_MBOX_VF_REGISTER_REPLY		= 3,
	ENIC_MBOX_VF_UNREGISTER_REQUEST		= 4,
	ENIC_MBOX_VF_UNREGISTER_REPLY		= 5,
	ENIC_MBOX_PF_LINK_STATE_NOTIF		= 6,
	ENIC_MBOX_PF_LINK_STATE_ACK		= 7,
	ENIC_MBOX_VF_ADD_DEL_MAC_REQUEST	= 10,
	ENIC_MBOX_VF_ADD_DEL_MAC_REPLY		= 11,
	ENIC_MBOX_PF_SET_ADMIN_MAC_NOTIF	= 12,
	ENIC_MBOX_PF_SET_ADMIN_MAC_ACK		= 13,
	ENIC_MBOX_VF_SET_PKT_FILTER_REQUEST	= 14,
	ENIC_MBOX_VF_SET_PKT_FILTER_REPLY	= 15,
	ENIC_MBOX_MAX
};

struct enic_mbox_hdr {
	__le16 src_vnic_id;
	__le16 dst_vnic_id;
	u8 msg_type;
	u8 flags;
	__le16 msg_len;
	__le64 msg_num;
};

struct enic_mbox_generic_reply {
	__le16 ret_major;
	__le16 ret_minor;
};

#define ENIC_MBOX_ERR_GENERIC		BIT(0)
#define ENIC_MBOX_ERR_VF_NOT_REGISTERED	BIT(1)
#define ENIC_MBOX_ERR_MSG_NOT_SUPPORTED	BIT(2)
#define ENIC_MBOX_ERR_MASK		(ENIC_MBOX_ERR_GENERIC | \
					 ENIC_MBOX_ERR_VF_NOT_REGISTERED | \
					 ENIC_MBOX_ERR_MSG_NOT_SUPPORTED)

/* ENIC_MBOX_VF_CAPABILITY_REQUEST / _REPLY */
#define ENIC_MBOX_CAP_VERSION_0		0
#define ENIC_MBOX_CAP_VERSION_1		1

struct enic_mbox_vf_capability_msg {
	__le32 version;
	__le32 reserved[32];
};

/* The embedded enic_mbox_generic_reply has 2-byte alignment, but the
 * __le32 members give this struct 4-byte natural alignment.  Receive
 * buffers come from kmalloc (>= 8-byte aligned), so there is no
 * misaligned access risk when casting from the receive buffer.
 */
struct enic_mbox_vf_capability_reply_msg {
	struct enic_mbox_generic_reply reply;
	__le32 version;
	__le32 reserved[32];
};

/* ENIC_MBOX_VF_REGISTER / _UNREGISTER */
struct enic_mbox_vf_register_reply_msg {
	struct enic_mbox_generic_reply reply;
};

/* ENIC_MBOX_PF_LINK_STATE_NOTIF / _ACK */
#define ENIC_MBOX_LINK_STATE_DISABLE	0
#define ENIC_MBOX_LINK_STATE_ENABLE	1

struct enic_mbox_pf_link_state_notif_msg {
	__le32 link_state;
};

struct enic_mbox_pf_link_state_ack_msg {
	struct enic_mbox_generic_reply ack;
};

/* ENIC_MBOX_PF_SET_ADMIN_MAC_NOTIF / _ACK */
struct enic_mbox_pf_set_admin_mac_notif_msg {
	u8 mac_addr[ETH_ALEN];
	__le16 pad;
};

/* ENIC_MBOX_VF_ADD_DEL_MAC_REQUEST / _REPLY */
#define ENIC_MAC_ADDR_FLAG_ADD		BIT(0)
#define ENIC_MAC_ADDR_FLAG_STATION	BIT(1)
#define ENIC_MAC_ADDR_FLAG_OVERFLOW	BIT(8)
#define ENIC_MAC_ADDR_FLAG_DUPLICATE	BIT(9)
#define ENIC_MAC_ADDR_FLAG_FAILED	BIT(10)
#define ENIC_MAC_ADDR_FLAG_NOT_FOUND	BIT(11)
#define ENIC_MAC_ADDR_FLAG_ERROR	BIT(12)
#define ENIC_MAC_ADDR_FLAG_NOT_PERMITTED BIT(13)
#define ENIC_MAC_ADDR_FLAG_INVALID	BIT(14)
#define ENIC_MAC_ADDR_FLAG_SKIPPED	BIT(15)

#define ENIC_MAC_ADDR_FLAG_REQUEST_MASK	GENMASK(7, 0)
#define ENIC_MAC_ADDR_FLAG_REPLY_MASK	GENMASK(15, 8)
#define ENIC_MAC_ADDR_FLAG_INDETERMINATE_MASK \
	(ENIC_MAC_ADDR_FLAG_FAILED | ENIC_MAC_ADDR_FLAG_ERROR)
#define ENIC_MAC_ADDR_FLAG_PERMANENT_MASK \
	(ENIC_MAC_ADDR_FLAG_OVERFLOW | ENIC_MAC_ADDR_FLAG_NOT_PERMITTED | \
	 ENIC_MAC_ADDR_FLAG_INVALID)
#define ENIC_MAC_ADDR_FLAG_ERROR_MASK	(ENIC_MAC_ADDR_FLAG_OVERFLOW | \
					 ENIC_MAC_ADDR_FLAG_FAILED | \
					 ENIC_MAC_ADDR_FLAG_ERROR | \
					 ENIC_MAC_ADDR_FLAG_NOT_PERMITTED | \
					 ENIC_MAC_ADDR_FLAG_INVALID | \
					 ENIC_MAC_ADDR_FLAG_SKIPPED)

/* The protocol permits replacing all perfect filters and the station address
 * in one request: one delete and one add operation for each address.
 */
#define ENIC_MBOX_MAX_MAC_OPS		130

struct enic_mac_addr {
	u8 addr[ETH_ALEN];
	__le16 flags;
};

struct enic_mbox_vf_add_del_mac_msg {
	__le16 num_addrs;
	__le16 pad;
	struct enic_mac_addr mac_addr[];
};

struct enic_mbox_vf_add_del_mac_reply_msg {
	struct enic_mbox_generic_reply reply;
	__le16 num_addrs;
	__le16 pad;
	struct enic_mac_addr mac_addr[];
};

/* ENIC_MBOX_VF_SET_PKT_FILTER_REQUEST / _REPLY */
struct enic_mbox_vf_set_pkt_filter_msg {
	__le16 flags;
	__le16 pad;
};

struct enic_mbox_vf_set_pkt_filter_reply_msg {
	struct enic_mbox_generic_reply reply;
};

#define ENIC_MBOX_DST_PF	0xFFFF

struct enic;

void enic_mbox_init(struct enic *enic);
int enic_mbox_send_msg(struct enic *enic, u8 msg_type, u16 dst_vnic_id,
		       void *payload, u16 payload_len);
int enic_mbox_send_link_state(struct enic *enic, u16 vf_id, u32 link_state);
void enic_mbox_vf_link_state_reset(struct enic *enic);
void enic_mbox_vf_link_state_set_running(struct enic *enic, bool running);
void enic_mbox_vf_ack_cancel(struct enic *enic);
void enic_mbox_vf_require_reconnect(struct enic *enic);
int enic_mbox_vf_capability_check(struct enic *enic);
int enic_mbox_vf_register(struct enic *enic);
int enic_mbox_vf_unregister(struct enic *enic);
int enic_mbox_vf_add_del_macs(struct enic *enic,
			      struct enic_mac_addr *macs, u16 num_macs);
int enic_mbox_vf_add_del_mac(struct enic *enic, const u8 *addr, bool add,
			     bool station);
int enic_mbox_vf_set_pkt_filter(struct enic *enic, int directed, int multicast,
				int broadcast, int promisc, int allmulti,
				u16 *applied_flags);

#endif /* _ENIC_MBOX_H_ */
