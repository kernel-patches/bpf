// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU switch driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/switchdev.h>
#include <net/netevent.h>
#include <net/arp.h>
#include <net/route.h>
#include <linux/inetdevice.h>

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_nb.h"
#include "sw_fdb.h"
#include "sw_fib.h"
#include "sw_fl.h"
#include "sw_nb.h"
#include "sw_nb_v4.h"

int sw_nb_v4_netdev_event(struct notifier_block *unused,
			  unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_hw_addr *dev_addr;
	struct net_device *pf_dev;
	struct in_ifaddr *ifa;
	struct fib_entry *entry;
	struct in_device *idev;
	struct otx2_nic *pf;
	struct list_head *iter;
	struct net_device *lower;

	idev = __in_dev_get_rtnl(dev);
	if (!idev || !idev->ifa_list)
		return NOTIFY_DONE;

	ifa = rtnl_dereference(idev->ifa_list);

	entry = kcalloc(1, sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NOTIFY_DONE;

	entry->cmd = sw_nb_inetaddr_event_to_otx2_event(event, dev);
	entry->dst = (__force u32)htonl((__force u32)ifa->ifa_address);
	entry->dst_len = 32;
	entry->mac_valid = 1;
	entry->host = 1;

	pf_dev = dev;
	if (netif_is_bridge_master(dev))  {
		entry->bridge = 1;
		netdev_for_each_lower_dev(dev, lower, iter) {
			pf_dev = lower;
			break;
		}
	} else if (is_vlan_dev(dev)) {
		entry->vlan_valid = 1;
		pf_dev = vlan_dev_real_dev(dev);
		entry->vlan_tag = vlan_dev_vlan_id(dev);
	}

	pf = netdev_priv(pf_dev);
	entry->port_id = pf->pcifunc;

	for_each_dev_addr(dev, dev_addr) {
		ether_addr_copy(entry->mac, dev_addr->addr);
		break;
	}

	netdev_dbg(dev, "%s: pushing netdev event from HOST interface address %#x, %pM, dev=%s\n",
		   __func__, entry->dst, entry->mac, dev->name);
	sw_fib_add_to_list(pf_dev, entry, 1);

	return NOTIFY_DONE;
}

int sw_nb_v4_inetaddr_event(struct notifier_block *nb,
			    unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct net_device *lower, *pf_dev;
	struct netdev_hw_addr *dev_addr;
	struct fib_entry *entry;
	struct in_device *idev;
	struct list_head *iter;
	struct otx2_nic *pf;

	if (event != NETDEV_CHANGE &&
	    event != NETDEV_UP &&
	    event != NETDEV_DOWN) {
		return NOTIFY_DONE;
	}

	idev = __in_dev_get_rtnl(dev);
	if (!idev || !idev->ifa_list)
		return NOTIFY_DONE;

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	entry->cmd = sw_nb_inetaddr_event_to_otx2_event(event, dev);
	entry->dst = (__force u32)htonl((__force u32)ifa->ifa_address);
	entry->dst_len = 32;
	entry->mac_valid = 1;
	entry->host = 1;

	pf_dev = dev;
	if (netif_is_bridge_master(dev))  {
		entry->bridge = 1;
		netdev_for_each_lower_dev(dev, lower, iter) {
			pf_dev = lower;
			break;
		}
	} else if (is_vlan_dev(dev)) {
		entry->vlan_valid = 1;
		pf_dev = vlan_dev_real_dev(dev);
		entry->vlan_tag = vlan_dev_vlan_id(dev);
	}

	pf = netdev_priv(pf_dev);
	entry->port_id = pf->pcifunc;

	for_each_dev_addr(dev, dev_addr) {
		ether_addr_copy(entry->mac, dev_addr->addr);
		break;
	}

	netdev_dbg(dev, "%s: pushing inetaddr event from HOST interface address %#x, %pM, %s\n",
		   __func__, entry->dst, entry->mac, dev->name);

	sw_fib_add_to_list(pf_dev, entry, 1);
	return NOTIFY_DONE;
}

int sw_nb_v4_fib_event(struct notifier_block *nb,
		       unsigned long event, void *ptr)
{
	struct fib_entry_notifier_info *fen_info = ptr;
	struct fib_entry *entries, *iter;
	struct net_device *dev, *pf_dev = NULL;
	struct netdev_hw_addr *dev_addr;
	struct net_device *lower;
	struct list_head *lh;
	struct neighbour *neigh;
	struct fib_nh *fib_nh;
	struct fib_info *fi;
	struct otx2_nic *pf;
	u32 *haddr;
	int hcnt = 0;
	int cnt, i;

	/* Process only UNICAST routes add or del */
	if (fen_info->type != RTN_UNICAST)
		return NOTIFY_DONE;

	fi = fen_info->fi;
	if (!fi)
		return NOTIFY_DONE;

	if (fi->fib_nh_is_v6) {
		struct net_device *log_dev = (fi->fib_nhs > 0) ?
			fi->fib_nh->fib_nh_dev : NULL;

		if (log_dev)
			netdev_dbg(log_dev, "%s: Received v6 notification\n",
				   __func__);
		return NOTIFY_DONE;
	}

	entries = kcalloc(fi->fib_nhs, sizeof(*entries), GFP_ATOMIC);
	if (!entries)
		return NOTIFY_DONE;

	haddr = kcalloc(fi->fib_nhs, sizeof(u32), GFP_ATOMIC);
	if (!haddr) {
		kfree(entries);
		return NOTIFY_DONE;
	}

	iter = entries;
	fib_nh = fi->fib_nh;
	for (i = 0; i < fi->fib_nhs; i++, fib_nh++) {
		dev = fib_nh->fib_nh_dev;

		if (!dev)
			continue;

		if (dev->type != ARPHRD_ETHER)
			continue;

		if (!sw_nb_is_valid_dev(dev))
			continue;

		iter->cmd = sw_nb_fib_event_to_otx2_event(event, dev);
		iter->dst = fen_info->dst;
		iter->dst_len = fen_info->dst_len;
		iter->gw = (__force u32)htonl((__force u32)fib_nh->fib_nh_gw4);

		netdev_dbg(dev, "%s: FIB route Rule cmd=%lld dst=%#x dst_len=%d gw=%#x\n",
			   __func__, iter->cmd, iter->dst, iter->dst_len, iter->gw);

		pf_dev = dev;
		if (netif_is_bridge_master(dev))  {
			iter->bridge = 1;
			netdev_for_each_lower_dev(dev, lower, lh) {
				pf_dev = lower;
				break;
			}
		} else if (is_vlan_dev(dev)) {
			iter->vlan_valid = 1;
			pf_dev = vlan_dev_real_dev(dev);
			iter->vlan_tag = vlan_dev_vlan_id(dev);
		}

		pf = netdev_priv(pf_dev);
		iter->port_id = pf->pcifunc;

		if (!fib_nh->fib_nh_gw4) {
			if (iter->dst || iter->dst_len)
				iter++;

			continue;
		}
		iter->gw_valid = 1;

		if (fib_nh->nh_saddr)
			haddr[hcnt++] = (__force u32)fib_nh->nh_saddr;

		rcu_read_lock();
		neigh = ip_neigh_gw4(fib_nh->fib_nh_dev, fib_nh->fib_nh_gw4);
		if (!neigh) {
			rcu_read_unlock();
			iter++;
			continue;
		}

		if (is_valid_ether_addr(neigh->ha)) {
			iter->mac_valid = 1;
			ether_addr_copy(iter->mac, neigh->ha);
		}

		iter++;
		rcu_read_unlock();
	}

	cnt = iter - entries;
	if (!cnt) {
		kfree(entries);
		kfree(haddr);
		return NOTIFY_DONE;
	}

	netdev_dbg(pf_dev, "pf_dev is %s cnt=%d\n", pf_dev->name, cnt);

	sw_fib_add_to_list(pf_dev, entries, cnt);

	if (!hcnt) {
		kfree(haddr);
		return NOTIFY_DONE;
	}

	entries = kcalloc(hcnt, sizeof(*entries), GFP_ATOMIC);
	if (!entries) {
		kfree(haddr);
		return NOTIFY_DONE;
	}

	iter = entries;

	for (i = 0; i < hcnt; i++, iter++) {
		iter->cmd = sw_nb_fib_event_to_otx2_event(event, pf_dev);
		iter->dst = (__force u32)htonl(haddr[i]);
		iter->dst_len = 32;
		iter->mac_valid = 1;
		iter->host = 1;
		iter->port_id = pf->pcifunc;

		for_each_dev_addr(pf_dev, dev_addr) {
			ether_addr_copy(iter->mac, dev_addr->addr);
			break;
		}

		netdev_dbg(pf_dev, "%s: FIB host  Rule cmd=%lld dst=%#x dst_len=%d gw=%#x %s\n",
			   __func__, iter->cmd, iter->dst, iter->dst_len, iter->gw, pf_dev->name);
	}
	sw_fib_add_to_list(pf_dev, entries, hcnt);
	kfree(haddr);
	return NOTIFY_DONE;
}

int sw_nb_net_v4_neigh_update(struct notifier_block *nb,
			      unsigned long event, void *ptr)
{
	struct net_device *lower, *pf_dev;
	struct neighbour *n = ptr;
	struct fib_entry *entry;
	struct list_head *iter;
	struct otx2_nic *pf;

	if (n->tbl != &arp_tbl)
		return NOTIFY_DONE;

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	entry->cmd = OTX2_NEIGH_UPDATE;
	entry->dst = (__force u32)htonl(*(u32 *)n->primary_key);
	entry->dst_len = n->tbl->key_len * 8;
	entry->mac_valid = 1;
	entry->nud_state = n->nud_state;
	neigh_ha_snapshot(entry->mac, n, n->dev);
	ether_addr_copy(entry->mac, n->ha);

	pf_dev = n->dev;

	rcu_read_lock();
	if (netif_is_bridge_master(n->dev))  {
		entry->bridge = 1;
		/* Get first lower device thru which we can send MBOX to AF */
		netdev_for_each_lower_dev(n->dev, lower, iter) {
			pf_dev = lower;
			break;
		}
	} else if (is_vlan_dev(n->dev)) {
		entry->vlan_valid = 1;
		pf_dev = vlan_dev_real_dev(n->dev);
		entry->vlan_tag = vlan_dev_vlan_id(n->dev);
	}

	pf = netdev_priv(pf_dev);
	entry->port_id = pf->pcifunc;

	sw_fib_add_to_list(pf_dev, entry, 1);
	rcu_read_unlock();

	return NOTIFY_DONE;
}
