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
#include <net/addrconf.h>
#include <net/ip6_fib.h>
#include <net/nexthop.h>

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_nb.h"
#include "sw_fdb.h"
#include "sw_fib.h"
#include "sw_fl.h"
#include "sw_nb.h"
#include "sw_nb_v6.h"

#if IS_ENABLED(CONFIG_IPV6)

int sw_nb_v6_netdev_event(struct notifier_block *unused,
			  unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_hw_addr *dev_addr;
	struct inet6_ifaddr *ifp;
	struct fib_entry *entry;
	struct inet6_dev *i6dev;
	struct otx2_nic *pf;

	i6dev = __in6_dev_get(dev);

	rcu_read_lock();
	ifp = list_first_entry_or_null(&i6dev->addr_list,
				       struct inet6_ifaddr,  if_list);
	if (!ifp) {
		rcu_read_unlock();
		return NOTIFY_DONE;
	}

	if (ipv6_addr_type(&ifp->addr) & IPV6_ADDR_LINKLOCAL) {
		rcu_read_unlock();
		return NOTIFY_DONE;
	}

	pf = netdev_priv(dev);

	entry = kcalloc(1, sizeof(*entry), GFP_KERNEL);
	entry->cmd = sw_nb_inetaddr_event_to_otx2_event(event, dev);
	memcpy(entry->dst6, &ifp->addr, sizeof(entry->dst6));
	entry->dst6_plen = ifp->prefix_len;
	entry->host = 1;
	entry->ipv6 = 1;
	entry->port_id = pf->pcifunc;

	for_each_dev_addr(dev, dev_addr) {
		entry->mac_valid = 1;
		ether_addr_copy(entry->mac, dev_addr->addr);
		break;
	}

	netdev_dbg(dev, "netdev event %pM plen=%u mac=%pM\n",
		   &ifp->addr, ifp->prefix_len, entry->mac);
	sw_fib_add_to_list(dev, entry, 1);
	rcu_read_unlock();
	return NOTIFY_DONE;
}

int sw_nb_v6_fib_event(struct notifier_block *nb,
		       unsigned long event, void *ptr)
{
	struct fib6_entry_notifier_info *f6_eni;
	struct fib_notifier_info *info = ptr;
	struct net_device *fib_dev;
	struct fib_entry *entry;
	struct fib6_info *f6i;
	struct neighbour *neigh;
	struct fib6_nh *nh6;
	struct otx2_nic *pf;
	struct rt6key *key;

	f6_eni = container_of(info, struct fib6_entry_notifier_info, info);
	f6i = f6_eni->rt;

	fib_dev = fib6_info_nh_dev(f6i);

	if (!fib_dev)
		return NOTIFY_DONE;

	if (fib_dev->type != ARPHRD_ETHER)
		return NOTIFY_DONE;

	if (!sw_nb_is_cavium_dev(fib_dev))
		return NOTIFY_DONE;

	if (f6i->fib6_type != RTN_UNICAST)
		return NOTIFY_DONE;

	key = &f6i->fib6_dst;
	/* TODO: vlan and bridge support */
	if (ipv6_addr_type(&key->addr) & IPV6_ADDR_LINKLOCAL)
		return NOTIFY_DONE;

	netdev_dbg(fib_dev, "fib6dst rt6key.addr=%pI6c len=%u\n", &key->addr,
		   key->plen);

	netdev_dbg(fib_dev, "fib6flags=%#x proto=%u type=%u\n",
		   f6i->fib6_flags, f6i->fib6_protocol, f6i->fib6_type);

	nh6 = f6i->nh ? nexthop_fib6_nh(f6i->nh) : f6i->fib6_nh;
	netdev_dbg(nh6->fib_nh_dev ? nh6->fib_nh_dev : fib_dev,
		   "nh family=%u dev=%s  gw=%pI6c gwfamily=%u\n",
		   nh6->fib_nh_family,
		   nh6->fib_nh_dev ? nh6->fib_nh_dev->name : "No dev",
		   &nh6->fib_nh_gw6, nh6->fib_nh_gw_family);

	pf = netdev_priv(fib_dev);

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NOTIFY_DONE;

	entry->cmd = sw_nb_fib_event_to_otx2_event(event, fib_dev);
	entry->ipv6 = 1;
	entry->port_id = pf->pcifunc;
	memcpy(entry->dst6, &key->addr, sizeof(entry->dst6));
	entry->dst6_plen = key->plen;

	memcpy(entry->gw6, &nh6->fib_nh_gw6, sizeof(nh6->fib_nh_gw6));
	entry->gw_valid = !!(ipv6_addr_type(&nh6->fib_nh_gw6) & IPV6_ADDR_UNICAST);

	rcu_read_lock();
	neigh = ip_neigh_gw6(fib_dev, &nh6->fib_nh_gw6);
	if (!neigh) {
		rcu_read_unlock();
		kfree(entry);
		return NOTIFY_DONE;
	}

	if (is_valid_ether_addr(neigh->ha)) {
		entry->mac_valid = 1;
		ether_addr_copy(entry->mac, neigh->ha);
		netdev_dbg(fib_dev, "fib found MAC=%pM\n", entry->mac);
	}

	sw_fib_add_to_list(fib_dev, entry, 1);
	rcu_read_unlock();

	return NOTIFY_DONE;
}

int sw_nb_net_v6_neigh_update(struct notifier_block *nb,
			      unsigned long event, void *ptr)
{
	struct neighbour *n = ptr;
	struct fib_entry *entry;
	struct net_device *pf_dev;
	struct otx2_nic *pf;

	if (n->tbl != &nd_tbl)
		return NOTIFY_DONE;

	if (ipv6_addr_type((struct in6_addr *)n->primary_key) & IPV6_ADDR_LINKLOCAL)
		return NOTIFY_DONE;

	pf_dev = n->dev;
	pf = netdev_priv(pf_dev);

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	entry->cmd = OTX2_NEIGH_UPDATE;

	entry->dst6_plen = n->tbl->key_len * 8;
	memcpy(entry->dst6, (struct in6_addr *)n->primary_key,
	       sizeof(entry->dst6));
	entry->ipv6 = 1;
	entry->nud_state = n->nud_state;
	ether_addr_copy(entry->mac, n->ha);
	entry->mac_valid = 1;
	entry->port_id = pf->pcifunc;

	sw_fib_add_to_list(pf_dev, entry, 1);

	netdev_dbg(n->dev, "v6 neigh update %pI6 mac=%pM plen=%u\n",
		   n->primary_key, n->ha, n->tbl->key_len * 8);

	return NOTIFY_DONE;
}

int sw_nb_v6_inetaddr_event(struct notifier_block *nb,
			    unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net_device *dev = ifa6->idev->dev;
	struct netdev_hw_addr *dev_addr;
	struct fib_entry *entry;
	struct otx2_nic *pf;

	if (event != NETDEV_CHANGE &&
	    event != NETDEV_UP &&
	    event != NETDEV_DOWN) {
		return NOTIFY_DONE;
	}

	if (dev->type != ARPHRD_ETHER)
		return NOTIFY_DONE;

	if (!sw_nb_is_cavium_dev(dev))
		return NOTIFY_DONE;

	if (ipv6_addr_type(&ifa6->addr) & IPV6_ADDR_LINKLOCAL)
		return NOTIFY_DONE;

	pf = netdev_priv(dev);

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	entry->cmd = sw_nb_inetaddr_event_to_otx2_event(event, dev);
	memcpy(entry->dst6, &ifa6->addr, sizeof(entry->dst6));
	entry->dst6_plen = ifa6->prefix_len;
	entry->mac_valid = 1;
	entry->host = 1;
	entry->ipv6 = 1;
	entry->port_id = pf->pcifunc;

	for_each_dev_addr(dev, dev_addr) {
		ether_addr_copy(entry->mac, dev_addr->addr);
		entry->mac_valid = 1;
		break;
	}

	sw_fib_add_to_list(dev, entry, 1);

	netdev_dbg(dev, "inetaddr addr=%pI6c len=%u %pM\n",
		   &ifa6->addr, ifa6->prefix_len, entry->mac);

	return NOTIFY_DONE;
}
#endif
