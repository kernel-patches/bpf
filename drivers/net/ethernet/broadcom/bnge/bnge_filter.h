/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Broadcom */

#ifndef _BNGE_FILTER_H_
#define _BNGE_FILTER_H_

#include <linux/jhash.h>

enum {
	BNGE_FLTR_TYPE_L2	= 1,
	BNGE_FLTR_TYPE_NTUPLE	= 2
};

enum {
	BNGE_FLTR_VALID,
	BNGE_FLTR_FW_DELETED
};

enum {
	BNGE_ACT_DROP		= 0x1,
	BNGE_ACT_RING_DST	= 0x2,
	BNGE_ACT_NO_AGING	= 0x4,
	BNGE_ACT_RSS_CTX	= 0x8
};

#define BNGE_MAX_L2_FLTRS	128
#define BNGE_MAX_NTUPLE_FLTRS	(8 << 10)

struct bnge_filter_base {
	struct hlist_node	hlist;
	struct list_head	list_node;
	__le64			filter_id;
	u8			type;
	u8			flags;
	u16			sw_id;
	u16			rxq;
	u16			fw_vnic_id;
	u16			vf_idx;
	unsigned long		state;

	struct rcu_head		rcu;
};

struct bnge_l2_key {
	union {
		struct {
			u8	dst_mac_addr[ETH_ALEN];
			u16	vlan;
		};
		u32	filter_key;
	};
};

#define BNGE_L2_KEY_SIZE	(sizeof(struct bnge_l2_key) / 4)
struct bnge_l2_filter {
	/* base filter must be the first member */
	struct bnge_filter_base	base;
	struct bnge_l2_key	l2_key;
};

struct bnge_ipv4_tuple {
	struct flow_dissector_key_ipv4_addrs v4addrs;
	struct flow_dissector_key_ports ports;
};

struct bnge_ipv6_tuple {
	struct flow_dissector_key_ipv6_addrs v6addrs;
	struct flow_dissector_key_ports ports;
};

struct bnge_flow_masks {
	struct flow_dissector_key_ports ports;
	struct flow_dissector_key_addrs addrs;
};

extern const struct bnge_flow_masks BNGE_FLOW_MASK_NONE;
extern const struct bnge_flow_masks BNGE_FLOW_IPV6_MASK_ALL;
extern const struct bnge_flow_masks BNGE_FLOW_IPV4_MASK_ALL;

struct bnge_ntuple_filter {
	/* base filter must be the first member */
	struct bnge_filter_base	base;
	struct flow_keys	fkeys;
	struct bnge_flow_masks	fmasks;
	__le64			l2_filter_id;
	u32			flow_id;
};

#define BNGE_L2_FLTR_IS_NTP_MAC(fltr)   ((fltr)->base.flags)

#define BNGE_FLTR_ID_INVALID	cpu_to_le64(0xffffffffffffffffULL)

void bnge_free_ntp_fltrs(struct bnge_net *bn, bool skip_user_filters);
u32 bnge_get_ntp_filter_idx(struct bnge_net *bn, struct flow_keys *fkeys,
			    const struct sk_buff *skb);
int bnge_insert_ntp_filter(struct bnge_net *bn, struct bnge_ntuple_filter *fltr,
			   u32 idx);
struct bnge_ntuple_filter *
bnge_lookup_ntp_filter_from_idx(struct bnge_net *bn,
				struct bnge_ntuple_filter *fltr, u32 idx);
void bnge_del_l2_filter(struct bnge_net *bn, struct bnge_l2_filter *fltr);
void bnge_del_l2_filter_rcu(struct bnge_net *bn, struct bnge_l2_filter *fltr);
struct bnge_l2_filter *bnge_lookup_l2_filter(struct bnge_net *bn,
					     struct bnge_l2_key *key,
					     u32 idx);
__le64 bnge_lookup_l2_filter_rcu(struct bnge_net *bn,
				 struct bnge_l2_key *key,
				 u32 idx);
void bnge_free_l2_filters(struct bnge_net *bn);
int bnge_hwrm_set_vnic_filter(struct bnge_net *bn, u16 vnic_id, u16 idx,
			      const u8 *mac_addr);
struct bnge_l2_filter *bnge_alloc_user_l2_filter(struct bnge_net *bn,
						 struct bnge_l2_key *key,
						 u8 flags);
int bnge_fltrs_mem(struct bnge_net *bn);
void bnge_del_ntp_filter(struct bnge_net *bn,
			 struct bnge_ntuple_filter *nfltr);
void bnge_del_ntp_filter_rcu(struct bnge_net *bn,
			     struct bnge_ntuple_filter *fltr);
void bnge_cfg_usr_fltrs(struct bnge_net *bn);
void bnge_clear_usr_fltrs(struct bnge_net *bn);
void bnge_cfg_ntp_filters(struct bnge_net *bn);
#endif /* _BNGE_FILTER_H_ */
