// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Broadcom.

#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/jhash.h>

#include "bnge.h"
#include "bnge_netdev.h"
#include "bnge_vnic.h"
#include "bnge_hwrm_lib.h"
#include "bnge_filter.h"

void bnge_del_l2_filter(struct bnge_net *bn, struct bnge_l2_filter *fltr)
{
	if (!refcount_dec_and_test(&fltr->refcnt))
		return;
	hlist_del_rcu(&fltr->base.hlist);
	kfree_rcu(fltr, base.rcu);
}

static void bnge_init_l2_filter(struct bnge_net *bn,
				struct bnge_l2_filter *fltr,
				struct bnge_l2_key *key, u32 idx)
{
	struct hlist_head *head;

	ether_addr_copy(fltr->l2_key.dst_mac_addr, key->dst_mac_addr);
	fltr->l2_key.vlan = key->vlan;
	fltr->base.type = BNGE_FLTR_TYPE_L2;

	head = &bn->l2_fltr_hash_tbl[idx];
	hlist_add_head_rcu(&fltr->base.hlist, head);
	refcount_set(&fltr->refcnt, 1);
}

static struct bnge_l2_filter *__bnge_lookup_l2_filter(struct bnge_net *bn,
						      struct bnge_l2_key *key,
						      u32 idx)
{
	struct bnge_l2_filter *fltr;
	struct hlist_head *head;

	head = &bn->l2_fltr_hash_tbl[idx];
	hlist_for_each_entry_rcu(fltr, head, base.hlist) {
		struct bnge_l2_key *l2_key = &fltr->l2_key;

		if (ether_addr_equal(l2_key->dst_mac_addr, key->dst_mac_addr) &&
		    l2_key->vlan == key->vlan)
			return fltr;
	}
	return NULL;
}

struct bnge_l2_filter *bnge_lookup_l2_filter(struct bnge_net *bn,
					     struct bnge_l2_key *key,
					     u32 idx)
{
	struct bnge_l2_filter *fltr;

	rcu_read_lock();
	fltr = __bnge_lookup_l2_filter(bn, key, idx);
	if (fltr)
		refcount_inc(&fltr->refcnt);
	rcu_read_unlock();
	return fltr;
}

static struct bnge_l2_filter *bnge_alloc_l2_filter(struct bnge_net *bn,
						   struct bnge_l2_key *key,
						   gfp_t gfp)
{
	struct bnge_l2_filter *fltr;
	u32 idx;

	idx = jhash2(&key->filter_key, BNGE_L2_KEY_SIZE, bn->hash_seed) &
	      BNGE_L2_FLTR_HASH_MASK;
	fltr = bnge_lookup_l2_filter(bn, key, idx);
	if (fltr)
		return fltr;

	fltr = kzalloc_obj(*fltr, gfp);
	if (!fltr)
		return ERR_PTR(-ENOMEM);

	bnge_init_l2_filter(bn, fltr, key, idx);
	return fltr;
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
	bnge_del_l2_filter(bn, fltr);
	return rc;
}
