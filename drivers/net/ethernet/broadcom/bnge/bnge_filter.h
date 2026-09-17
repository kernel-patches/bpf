/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Broadcom */

#ifndef _BNGE_FILTER_H_
#define _BNGE_FILTER_H_

enum {
	BNGE_FLTR_TYPE_L2	= 1
};

enum {
	BNGE_FLTR_VALID,
	BNGE_FLTR_FW_DELETED
};

struct bnge_filter_base {
	struct hlist_node	hlist;
	struct list_head	list_node;
	__le64			filter_id;
	u8			type;
	u8			flags;
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
	refcount_t		refcnt;
};

void bnge_del_l2_filter(struct bnge_net *bn, struct bnge_l2_filter *fltr);
struct bnge_l2_filter *bnge_lookup_l2_filter(struct bnge_net *bn,
					     struct bnge_l2_key *key,
					     u32 idx);
int bnge_hwrm_set_vnic_filter(struct bnge_net *bn, u16 vnic_id, u16 idx,
			      const u8 *mac_addr);
#endif /* _BNGE_FILTER_H_ */
