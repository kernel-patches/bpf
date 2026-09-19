// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Broadcom.

#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/jhash.h>
#include <net/netdev_lock.h>
#include <net/ipv6.h>

#include "bnge.h"
#include "bnge_netdev.h"
#include "bnge_vnic.h"
#include "bnge_hwrm_lib.h"
#include "bnge_filter.h"

#define BNGE_IPV6_MASK_ALL {{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}}
#define BNGE_IPV6_MASK_NONE {{{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}}

const struct bnge_flow_masks BNGE_FLOW_MASK_NONE = {
	.ports = {
		.src = 0,
		.dst = 0,
	},
	.addrs = {
		.v6addrs = {
			.src = BNGE_IPV6_MASK_NONE,
			.dst = BNGE_IPV6_MASK_NONE,
		},
	},
};

const struct bnge_flow_masks BNGE_FLOW_IPV6_MASK_ALL = {
	.ports = {
		.src = cpu_to_be16(0xffff),
		.dst = cpu_to_be16(0xffff),
	},
	.addrs = {
		.v6addrs = {
			.src = BNGE_IPV6_MASK_ALL,
			.dst = BNGE_IPV6_MASK_ALL,
		},
	},
};

const struct bnge_flow_masks BNGE_FLOW_IPV4_MASK_ALL = {
	.ports = {
		.src = cpu_to_be16(0xffff),
		.dst = cpu_to_be16(0xffff),
	},
	.addrs = {
		.v4addrs = {
			.src = cpu_to_be32(0xffffffff),
			.dst = cpu_to_be32(0xffffffff),
		},
	},
};

static bool bnge_is_usr_fltr(struct bnge_filter_base *fltr)
{
	return (fltr->type == BNGE_FLTR_TYPE_L2 &&
		fltr->flags & BNGE_ACT_RING_DST) ||
	       (fltr->type == BNGE_FLTR_TYPE_NTUPLE &&
		fltr->flags & BNGE_ACT_NO_AGING);
}

static void bnge_insert_usr_fltr(struct bnge_net *bn,
				 struct bnge_filter_base *fltr)
{
	if (!bnge_is_usr_fltr(fltr))
		return;

	INIT_LIST_HEAD(&fltr->list_node);
	list_add_tail(&fltr->list_node, &bn->usr_fltr_list);
	bn->user_fltr_count++;
}

static void bnge_del_usr_fltr_node(struct bnge_net *bn,
				   struct bnge_filter_base *fltr)
{
	if (!bnge_is_usr_fltr(fltr))
		return;

	if (!list_empty(&fltr->list_node)) {
		list_del_init(&fltr->list_node);
		bn->user_fltr_count--;
	}
}

void bnge_del_l2_filter_rcu(struct bnge_net *bn, struct bnge_l2_filter *lfltr)
{
	struct bnge_filter_base *fltr = &lfltr->base;

	hlist_del_rcu(&fltr->hlist);
	bnge_del_usr_fltr_node(bn, fltr);
	clear_bit(fltr->sw_id, bn->l2_fltr_bmap);
	bn->l2_fltr_count--;
	kfree_rcu(lfltr, base.rcu);
}

void bnge_del_l2_filter(struct bnge_net *bn, struct bnge_l2_filter *lfltr)
{
	struct bnge_filter_base *fltr = &lfltr->base;

	hlist_del(&fltr->hlist);
	bnge_del_usr_fltr_node(bn, fltr);
	clear_bit(fltr->sw_id, bn->l2_fltr_bmap);
	bn->l2_fltr_count--;
	kfree(fltr);
}

void bnge_del_ntp_filter(struct bnge_net *bn, struct bnge_ntuple_filter *nfltr)
{
	struct bnge_filter_base *fltr = &nfltr->base;

	hlist_del(&fltr->hlist);
	bnge_del_usr_fltr_node(bn, fltr);
	clear_bit(fltr->sw_id, bn->ntp_fltr_bmap);
	bn->ntp_fltr_count--;
	kfree(fltr);
}

void bnge_del_ntp_filter_rcu(struct bnge_net *bn,
			     struct bnge_ntuple_filter *fltr)
{
	spin_lock_bh(&bn->ntp_fltr_lock);
	hlist_del_rcu(&fltr->base.hlist);
	bnge_del_usr_fltr_node(bn, &fltr->base);
	clear_bit(fltr->base.sw_id, bn->ntp_fltr_bmap);
	bn->ntp_fltr_count--;
	spin_unlock_bh(&bn->ntp_fltr_lock);

	kfree_rcu(fltr, base.rcu);
}

static int bnge_init_l2_filter(struct bnge_net *bn,
			       struct bnge_l2_filter *fltr,
			       struct bnge_l2_key *key, u32 idx)
{
	struct hlist_head *head;
	int bit_id;

	ether_addr_copy(fltr->l2_key.dst_mac_addr, key->dst_mac_addr);
	fltr->l2_key.vlan = key->vlan;
	fltr->base.type = BNGE_FLTR_TYPE_L2;
	fltr->base.filter_id = BNGE_FLTR_ID_INVALID;

	bit_id = bitmap_find_free_region(bn->l2_fltr_bmap,
					 BNGE_MAX_L2_FLTRS, 0);
	if (bit_id < 0)
		return -ENOMEM;
	fltr->base.sw_id = (u16)bit_id;

	bn->l2_fltr_count++;

	head = &bn->l2_fltr_hash_tbl[idx];
	hlist_add_head_rcu(&fltr->base.hlist, head);
	bnge_insert_usr_fltr(bn, &fltr->base);
	return 0;
}

struct bnge_l2_filter *bnge_lookup_l2_filter(struct bnge_net *bn,
					     struct bnge_l2_key *key,
					     u32 idx)
{
	struct bnge_l2_filter *fltr;
	struct hlist_head *head;

	head = &bn->l2_fltr_hash_tbl[idx];
	hlist_for_each_entry(fltr, head, base.hlist) {
		struct bnge_l2_key *l2_key = &fltr->l2_key;

		if (ether_addr_equal(l2_key->dst_mac_addr, key->dst_mac_addr) &&
		    l2_key->vlan == key->vlan)
			return fltr;
	}
	return NULL;
}

__le64 bnge_lookup_l2_filter_rcu(struct bnge_net *bn,
				 struct bnge_l2_key *key,
				 u32 idx)
{
	__le64 id = BNGE_FLTR_ID_INVALID;
	struct bnge_l2_filter *fltr;
	struct hlist_head *head;

	rcu_read_lock();

	head = &bn->l2_fltr_hash_tbl[idx];
	hlist_for_each_entry_rcu(fltr, head, base.hlist) {
		struct bnge_l2_key *l2_key = &fltr->l2_key;

		if (ether_addr_equal(l2_key->dst_mac_addr, key->dst_mac_addr) &&
		    l2_key->vlan == key->vlan) {
			id = fltr->base.filter_id;
			break;
		}
	}

	rcu_read_unlock();
	return id;
}

static struct bnge_l2_filter *bnge_alloc_l2_filter(struct bnge_net *bn,
						   struct bnge_l2_key *key,
						   gfp_t gfp)
{
	struct bnge_l2_filter *fltr;
	u32 idx;
	int rc;

	idx = jhash2(&key->filter_key, BNGE_L2_KEY_SIZE, bn->hash_seed) &
	      BNGE_L2_FLTR_HASH_MASK;

	fltr = bnge_lookup_l2_filter(bn, key, idx);
	if (fltr)
		return ERR_PTR(-EEXIST);

	fltr = kzalloc_obj(*fltr, gfp);
	if (!fltr)
		return ERR_PTR(-ENOMEM);

	rc = bnge_init_l2_filter(bn, fltr, key, idx);
	if (rc) {
		kfree(fltr);
		fltr = ERR_PTR(rc);
	}

	return fltr;
}

struct bnge_l2_filter *bnge_alloc_user_l2_filter(struct bnge_net *bn,
						 struct bnge_l2_key *key,
						 u8 flags)
{
	struct bnge_l2_filter *fltr;
	u32 idx;
	int rc;

	idx = jhash2(&key->filter_key, BNGE_L2_KEY_SIZE, bn->hash_seed) &
	      BNGE_L2_FLTR_HASH_MASK;
	fltr = bnge_lookup_l2_filter(bn, key, idx);
	if (fltr) {
		fltr = ERR_PTR(-EEXIST);
		goto l2_filter_exit;
	}
	fltr = kzalloc_obj(*fltr, GFP_ATOMIC);
	if (!fltr) {
		fltr = ERR_PTR(-ENOMEM);
		goto l2_filter_exit;
	}
	fltr->base.flags = flags;
	rc = bnge_init_l2_filter(bn, fltr, key, idx);
	if (rc) {
		kfree(fltr);
		return ERR_PTR(rc);
	}

l2_filter_exit:
	return fltr;
}

void bnge_free_l2_filters(struct bnge_net *bn)
{
	int i;

	netdev_assert_locked_or_invisible(bn->netdev);

	for (i = 0; i < BNGE_L2_FLTR_HASH_SIZE; i++) {
		struct bnge_l2_filter *fltr;
		struct hlist_head *head;
		struct hlist_node *tmp;

		head = &bn->l2_fltr_hash_tbl[i];
		hlist_for_each_entry_safe(fltr, tmp, head, base.hlist)
			bnge_del_l2_filter(bn, fltr);
	}

	bitmap_free(bn->l2_fltr_bmap);
	bn->l2_fltr_bmap = NULL;
	bn->l2_fltr_count = 0;
}

void bnge_free_ntp_fltrs(struct bnge_net *bn, bool skip_user)
{
	int i;

	netdev_assert_locked_or_invisible(bn->netdev);

	/* Under netdev instance lock and all our NAPIs have been disabled.
	 * It's safe to delete the hash table.
	 */
	for (i = 0; i < BNGE_NTP_FLTR_HASH_SIZE; i++) {
		struct bnge_ntuple_filter *fltr;
		struct hlist_head *head;
		struct hlist_node *tmp;

		head = &bn->ntp_fltr_hash_tbl[i];
		hlist_for_each_entry_safe(fltr, tmp, head, base.hlist) {
			if (skip_user && bnge_is_usr_fltr(&fltr->base))
				continue;
			bnge_del_ntp_filter(bn, fltr);
		}
	}

	if (skip_user)
		return;

	bitmap_free(bn->ntp_fltr_bmap);
	bn->ntp_fltr_bmap = NULL;
	bn->ntp_fltr_count = 0;
}

static int bnge_alloc_l2_fltrs_mem(struct bnge_net *bn)
{
	int i, rc = 0;

	if (bn->l2_fltr_bmap)
		return 0;

	for (i = 0; i < BNGE_L2_FLTR_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&bn->l2_fltr_hash_tbl[i]);

	bn->l2_fltr_count = 0;
	bn->l2_fltr_bmap = bitmap_zalloc(BNGE_MAX_L2_FLTRS, GFP_KERNEL);

	if (!bn->l2_fltr_bmap)
		rc = -ENOMEM;

	return rc;
}

static int bnge_alloc_ntp_fltrs_mem(struct bnge_net *bn)
{
	struct bnge_dev *bd = bn->bd;
	int i, rc = 0;

	if (!(bn->priv_flags & BNGE_NET_EN_NTUPLE) || bn->ntp_fltr_bmap)
		return 0;

	for (i = 0; i < BNGE_NTP_FLTR_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&bn->ntp_fltr_hash_tbl[i]);

	bn->ntp_fltr_count = 0;
	bn->ntp_fltr_bmap = bitmap_zalloc(bd->max_fltr, GFP_KERNEL);

	if (!bn->ntp_fltr_bmap)
		rc = -ENOMEM;

	return rc;
}

int bnge_fltrs_mem(struct bnge_net *bn)
{
	bool ntp_alloced = !bn->ntp_fltr_bmap;
	int rc;

	rc = bnge_alloc_ntp_fltrs_mem(bn);
	if (rc)
		return rc;

	rc = bnge_alloc_l2_fltrs_mem(bn);
	if (rc)
		goto err_free_ntp_mem;

	return 0;

err_free_ntp_mem:
	if (ntp_alloced) {
		bitmap_free(bn->ntp_fltr_bmap);
		bn->ntp_fltr_bmap = NULL;
	}
	return rc;
}

#define BNGE_IPV4_4TUPLE(bd, fkeys)					\
	(((fkeys)->basic.ip_proto == IPPROTO_TCP &&			\
	  (bd)->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV4) ||	\
	 ((fkeys)->basic.ip_proto == IPPROTO_UDP &&			\
	  (bd)->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV4))

#define BNGE_IPV6_4TUPLE(bd, fkeys)					\
	(((fkeys)->basic.ip_proto == IPPROTO_TCP &&			\
	  (bd)->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_TCP_IPV6) ||	\
	 ((fkeys)->basic.ip_proto == IPPROTO_UDP &&			\
	  (bd)->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_UDP_IPV6))

static u32 bnge_get_rss_flow_tuple_len(struct bnge_dev *bd,
				       struct flow_keys *fkeys)
{
	if (fkeys->basic.n_proto == htons(ETH_P_IP)) {
		if (BNGE_IPV4_4TUPLE(bd, fkeys))
			return sizeof(fkeys->addrs.v4addrs) +
			       sizeof(fkeys->ports);

		if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV4)
			return sizeof(fkeys->addrs.v4addrs);
	}

	if (fkeys->basic.n_proto == htons(ETH_P_IPV6)) {
		if (BNGE_IPV6_4TUPLE(bd, fkeys))
			return sizeof(fkeys->addrs.v6addrs) +
			       sizeof(fkeys->ports);

		if (bd->rss_hash_cfg & VNIC_RSS_CFG_REQ_HASH_TYPE_IPV6)
			return sizeof(fkeys->addrs.v6addrs);
	}

	return 0;
}

static u32 bnge_toeplitz(struct bnge_net *bn, struct flow_keys *fkeys,
			 const unsigned char *key)
{
	u64 prefix = bn->toeplitz_prefix, hash = 0;
	struct bnge_ipv4_tuple tuple4;
	struct bnge_ipv6_tuple tuple6;
	struct bnge_dev *bd = bn->bd;
	u8 *four_tuple;
	int i, j, len;

	len = bnge_get_rss_flow_tuple_len(bd, fkeys);
	if (!len)
		return 0;

	if (fkeys->basic.n_proto == htons(ETH_P_IP)) {
		tuple4.v4addrs = fkeys->addrs.v4addrs;
		tuple4.ports = fkeys->ports;
		four_tuple = (u8 *)&tuple4;
	} else {
		tuple6.v6addrs = fkeys->addrs.v6addrs;
		tuple6.ports = fkeys->ports;
		four_tuple = (u8 *)&tuple6;
	}

	for (i = 0, j = 8; i < len; i++, j++) {
		u8 byte = four_tuple[i];
		int bit;

		for (bit = 0; bit < 8; bit++, prefix <<= 1, byte <<= 1) {
			if (byte & 0x80)
				hash ^= prefix;
		}
		prefix |= (j < HW_HASH_KEY_SIZE) ? key[j] : 0;
	}

	/* The valid part of the hash is in the upper 32 bits. */
	return (hash >> 32) & BNGE_NTP_FLTR_HASH_MASK;
}

u32 bnge_get_ntp_filter_idx(struct bnge_net *bn, struct flow_keys *fkeys,
			    const struct sk_buff *skb)
{
	struct bnge_vnic_info *vnic;

	if (skb)
		return skb_get_hash_raw(skb) & BNGE_NTP_FLTR_HASH_MASK;

	vnic = &bn->vnic_info[BNGE_VNIC_DEFAULT];
	return bnge_toeplitz(bn, fkeys, (void *)vnic->rss_hash_key);
}

static bool bnge_fltr_match(struct bnge_ntuple_filter *f1,
			    struct bnge_ntuple_filter *f2)
{
	struct bnge_flow_masks *masks1 = &f1->fmasks;
	struct bnge_flow_masks *masks2 = &f2->fmasks;
	struct flow_keys *keys1 = &f1->fkeys;
	struct flow_keys *keys2 = &f2->fkeys;

	if (keys1->basic.n_proto != keys2->basic.n_proto ||
	    keys1->basic.ip_proto != keys2->basic.ip_proto)
		return false;

	if (keys1->basic.n_proto == htons(ETH_P_IP)) {
		if (keys1->addrs.v4addrs.src != keys2->addrs.v4addrs.src ||
		    masks1->addrs.v4addrs.src != masks2->addrs.v4addrs.src ||
		    keys1->addrs.v4addrs.dst != keys2->addrs.v4addrs.dst ||
		    masks1->addrs.v4addrs.dst != masks2->addrs.v4addrs.dst)
			return false;
	} else {
		if (!ipv6_addr_equal(&keys1->addrs.v6addrs.src,
				     &keys2->addrs.v6addrs.src) ||
		    !ipv6_addr_equal(&masks1->addrs.v6addrs.src,
				     &masks2->addrs.v6addrs.src) ||
		    !ipv6_addr_equal(&keys1->addrs.v6addrs.dst,
				     &keys2->addrs.v6addrs.dst) ||
		    !ipv6_addr_equal(&masks1->addrs.v6addrs.dst,
				     &masks2->addrs.v6addrs.dst))
			return false;
	}

	return keys1->ports.src == keys2->ports.src &&
	       masks1->ports.src == masks2->ports.src &&
	       keys1->ports.dst == keys2->ports.dst &&
	       masks1->ports.dst == masks2->ports.dst &&
	       keys1->control.flags == keys2->control.flags &&
	       f1->l2_filter_id == f2->l2_filter_id;
}

int bnge_insert_ntp_filter(struct bnge_net *bn, struct bnge_ntuple_filter *fltr,
			   u32 idx)
{
	struct bnge_ntuple_filter *f;
	struct hlist_head *head;
	int bit_id;

	spin_lock_bh(&bn->ntp_fltr_lock);

	head = &bn->ntp_fltr_hash_tbl[idx];
	hlist_for_each_entry(f, head, base.hlist) {
		if (bnge_fltr_match(f, fltr)) {
			spin_unlock_bh(&bn->ntp_fltr_lock);
			return -EEXIST;
		}
	}

	bit_id = bitmap_find_free_region(bn->ntp_fltr_bmap,
					 bn->bd->max_fltr, 0);
	if (bit_id < 0) {
		spin_unlock_bh(&bn->ntp_fltr_lock);
		return -ENOMEM;
	}

	fltr->base.sw_id = (u16)bit_id;
	fltr->base.type = BNGE_FLTR_TYPE_NTUPLE;
	fltr->base.flags |= BNGE_ACT_RING_DST;

	head = &bn->ntp_fltr_hash_tbl[idx];
	hlist_add_head_rcu(&fltr->base.hlist, head);

	bnge_insert_usr_fltr(bn, &fltr->base);
	bn->ntp_fltr_count++;

	spin_unlock_bh(&bn->ntp_fltr_lock);

	return 0;
}

struct bnge_ntuple_filter *
bnge_lookup_ntp_filter_from_idx(struct bnge_net *bn,
				struct bnge_ntuple_filter *fltr, u32 idx)
{
	struct bnge_ntuple_filter *f;
	struct hlist_head *head;

	head = &bn->ntp_fltr_hash_tbl[idx];
	hlist_for_each_entry_rcu(f, head, base.hlist) {
		if (bnge_fltr_match(f, fltr))
			return f;
	}
	return NULL;
}

int bnge_hwrm_set_vnic_filter(struct bnge_net *bn, u16 vnic_id, u16 idx,
			      const u8 *mac_addr)
{
	struct bnge_l2_filter *fltr;
	struct bnge_l2_key key;
	int rc;

	ether_addr_copy(key.dst_mac_addr, mac_addr);
	key.vlan = 0;
	fltr = bnge_alloc_l2_filter(bn, &key, GFP_KERNEL);
	if (IS_ERR(fltr))
		return PTR_ERR(fltr);

	fltr->base.fw_vnic_id = bn->vnic_info[vnic_id].fw_vnic_id;
	rc = bnge_hwrm_l2_filter_alloc(bn->bd, fltr);
	if (rc)
		goto err_del_l2_filter;
	bn->vnic_info[vnic_id].l2_filters[idx] = fltr;
	return rc;

err_del_l2_filter:
	bnge_del_l2_filter_rcu(bn, fltr);
	return rc;
}

static void bnge_cfg_one_usr_fltr(struct bnge_net *bn,
				  struct bnge_filter_base *fltr)
{
	struct bnge_ntuple_filter *ntp_fltr;
	struct bnge_l2_filter *l2_fltr;

	if (list_empty(&fltr->list_node))
		return;

	if (fltr->type == BNGE_FLTR_TYPE_NTUPLE) {
		ntp_fltr = container_of(fltr, struct bnge_ntuple_filter, base);
		l2_fltr = bn->vnic_info[BNGE_VNIC_DEFAULT].l2_filters[0];
		ntp_fltr->l2_filter_id = l2_fltr->base.filter_id;
		if (bnge_hwrm_cfa_ntuple_filter_alloc(bn->bd, ntp_fltr)) {
			netdev_err(bn->netdev,
				   "restoring previously configured ntuple filter id %d failed\n",
				   fltr->sw_id);
			bnge_del_ntp_filter_rcu(bn, ntp_fltr);
		}
	} else if (fltr->type == BNGE_FLTR_TYPE_L2) {
		l2_fltr = container_of(fltr, struct bnge_l2_filter, base);
		if (bnge_hwrm_l2_filter_alloc(bn->bd, l2_fltr)) {
			netdev_err(bn->netdev,
				   "restoring previously configured l2 filter id %d failed\n",
				   fltr->sw_id);
			bnge_del_l2_filter_rcu(bn, l2_fltr);
		}
	}
}

void bnge_cfg_usr_fltrs(struct bnge_net *bn)
{
	struct bnge_filter_base *usr_fltr, *tmp;

	list_for_each_entry_safe(usr_fltr, tmp, &bn->usr_fltr_list, list_node)
		bnge_cfg_one_usr_fltr(bn, usr_fltr);
}

void bnge_clear_usr_fltrs(struct bnge_net *bn)
{
	struct bnge_filter_base *usr_fltr, *tmp;
	struct bnge_ntuple_filter *ntp_fltr;
	struct bnge_l2_filter *l2_fltr;

	netdev_assert_locked(bn->netdev);

	list_for_each_entry_safe(usr_fltr, tmp, &bn->usr_fltr_list, list_node) {
		if (usr_fltr->type == BNGE_FLTR_TYPE_NTUPLE) {
			ntp_fltr = container_of(usr_fltr,
						struct bnge_ntuple_filter,
						base);
			bnge_del_ntp_filter(bn, ntp_fltr);
		} else if (usr_fltr->type == BNGE_FLTR_TYPE_L2) {
			l2_fltr = container_of(usr_fltr, struct bnge_l2_filter,
					       base);
			bnge_del_l2_filter(bn, l2_fltr);
		}
	}
}

void bnge_cfg_ntp_filters(struct bnge_net *bn)
{
#ifdef CONFIG_RFS_ACCEL
	struct bnge_ntuple_filter *fltr, *tmp;
	LIST_HEAD(install_list);
	LIST_HEAD(expire_list);
	int i, rc;

	rcu_read_lock();
	for (i = 0; i < BNGE_NTP_FLTR_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(fltr, &bn->ntp_fltr_hash_tbl[i],
					 base.hlist) {
			if (test_bit(BNGE_FLTR_VALID, &fltr->base.state)) {
				if (fltr->base.flags & BNGE_ACT_NO_AGING)
					continue;
				if (rps_may_expire_flow(bn->netdev,
							fltr->base.rxq,
							fltr->flow_id,
							fltr->base.sw_id))
					list_add(&fltr->base.list_node,
						 &expire_list);
			} else {
				list_add(&fltr->base.list_node, &install_list);
			}
		}
	}
	rcu_read_unlock();

	list_for_each_entry_safe(fltr, tmp, &install_list, base.list_node) {
		list_del_init(&fltr->base.list_node);
		rc = bnge_hwrm_cfa_ntuple_filter_alloc(bn->bd, fltr);
		if (rc)
			bnge_del_ntp_filter_rcu(bn, fltr);
		else
			set_bit(BNGE_FLTR_VALID, &fltr->base.state);
	}

	list_for_each_entry_safe(fltr, tmp, &expire_list, base.list_node) {
		list_del_init(&fltr->base.list_node);
		bnge_hwrm_cfa_ntuple_filter_free(bn->bd, fltr);
		bnge_del_ntp_filter_rcu(bn, fltr);
	}
#endif
}
