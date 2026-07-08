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

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_nb.h"
#include "sw_fdb.h"
#include "sw_fib.h"
#include "sw_fl.h"
#include "sw_nb_v4.h"
#include "sw_nb_v6.h"

/* PF netdev for netdev_* logging when notifier info has no device */
static struct net_device *sw_nb_pf_netdev;

static const char *sw_nb_cmd2str[OTX2_CMD_MAX] = {
	[OTX2_DEV_UP]  = "OTX2_DEV_UP",
	[OTX2_DEV_DOWN] = "OTX2_DEV_DOWN",
	[OTX2_DEV_CHANGE] = "OTX2_DEV_CHANGE",
	[OTX2_NEIGH_UPDATE] = "OTX2_NEIGH_UPDATE",
	[OTX2_FIB_ENTRY_REPLACE] = "OTX2_FIB_ENTRY_REPLACE",
	[OTX2_FIB_ENTRY_ADD] = "OTX2_FIB_ENTRY_ADD",
	[OTX2_FIB_ENTRY_DEL] = "OTX2_FIB_ENTRY_DEL",
	[OTX2_FIB_ENTRY_APPEND] = "OTX2_FIB_ENTRY_APPEND",
};

const char *sw_nb_get_cmd2str(int cmd)
{
	return sw_nb_cmd2str[cmd];
}
EXPORT_SYMBOL(sw_nb_get_cmd2str);

bool sw_nb_is_cavium_dev(struct net_device *netdev)
{
	struct pci_dev *pdev;
	struct device *dev;

	dev = netdev->dev.parent;
	if (!dev || dev->bus != &pci_bus_type)
		return false;

	pdev = to_pci_dev(dev);
	if (pdev->vendor != PCI_VENDOR_ID_CAVIUM)
		return false;

	return true;
}

static int sw_nb_check_slaves(struct net_device *dev,
			      struct netdev_nested_priv *priv)
{
	int *cnt;

	if (!priv->flags)
		return 0;

	priv->flags &= sw_nb_is_cavium_dev(dev);
	if (priv->flags) {
		cnt = priv->data;
		(*cnt)++;
	}

	return 0;
}

bool sw_nb_is_valid_dev(struct net_device *netdev)
{
	struct netdev_nested_priv priv;
	struct net_device *br;
	int cnt = 0;

	priv.flags = true;
	priv.data = &cnt;

	if (netif_is_bridge_master(netdev) || is_vlan_dev(netdev)) {
		/* sw_nb_is_valid_dev() is invoked in notifier callback context, so
		 * rtnl_lcok is already acquired
		 */
		netdev_walk_all_lower_dev(netdev, sw_nb_check_slaves, &priv);
		return priv.flags && !!*(int *)priv.data;
	}

	if (netif_is_bridge_port(netdev)) {
		br = netdev_master_upper_dev_get_rcu(netdev);
		if (!br)
			return false;

		netdev_walk_all_lower_dev(br, sw_nb_check_slaves, &priv);
		return priv.flags && !!*(int *)priv.data;
	}

	return sw_nb_is_cavium_dev(netdev);
}

static int sw_nb_fdb_event(struct notifier_block *unused,
			   unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct switchdev_notifier_fdb_info *fdb_info = ptr;
	int rc = 0;

	if (!sw_nb_is_valid_dev(dev))
		return NOTIFY_DONE;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		if (fdb_info->is_local)
			break;
		rc = sw_fdb_add_to_list(dev, (u8 *)fdb_info->addr, true);
		break;

	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		if (fdb_info->is_local)
			break;
		rc = sw_fdb_add_to_list(dev, (u8 *)fdb_info->addr, false);
		break;

	default:
		return NOTIFY_DONE;
	}

	if (rc)
		netdev_err(dev, "%s: Error to add to list\n", __func__);

	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_fdb = {
	.notifier_call = sw_nb_fdb_event,
};

static void __maybe_unused
sw_nb_fib_event_dump(unsigned long event, void *ptr)
{
	struct fib_entry_notifier_info *fen_info = ptr;
	struct net_device *log_dev;
	struct fib_nh *fib_nh;
	struct fib_info *fi;
	int i;

	fi = fen_info->fi;
	log_dev = (fi && fi->fib_nhs) ? fi->fib_nh->fib_nh_dev : sw_nb_pf_netdev;
	if (log_dev)
		netdev_info(log_dev, "%s: FIB event=%lu dst=%#x dstlen=%u type=%u\n",
			    __func__, event, fen_info->dst, fen_info->dst_len,
			    fen_info->type);

	if (!fi)
		return;

	fib_nh = fi->fib_nh;
	for (i = 0; i < fi->fib_nhs; i++, fib_nh++) {
		if (!fib_nh->fib_nh_dev)
			continue;
		netdev_info(fib_nh->fib_nh_dev,
			    "%s: dev=%s saddr=%#x gw=%#x\n",
			    __func__, fib_nh->fib_nh_dev->name,
			    fib_nh->nh_saddr, fib_nh->fib_nh_gw4);
	}
}

#define SWITCH_NB_FIB_EVENT_DUMP(...) \
	sw_nb_fib_event_dump(__VA_ARGS__)

int sw_nb_fib_event_to_otx2_event(int event, struct net_device *netdev)
{
	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
		return OTX2_FIB_ENTRY_REPLACE;
	case FIB_EVENT_ENTRY_ADD:
		return OTX2_FIB_ENTRY_ADD;
	case FIB_EVENT_ENTRY_DEL:
		return OTX2_FIB_ENTRY_DEL;
	default:
		break;
	}

	netdev_err(netdev, "Wrong FIB event %d\n", event);
	return -1;
}

static int sw_nb_fib_event(struct notifier_block *nb,
			   unsigned long event, void *ptr)
{
	struct fib_notifier_info *info = ptr;

	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
		break;
	default:
		if (sw_nb_pf_netdev)
			netdev_dbg(sw_nb_pf_netdev,
				   "%s: Won't process FIB event %lu\n",
				   __func__, event);
		return NOTIFY_DONE;
	}

	switch (info->family) {
	case AF_INET:
		return sw_nb_v4_fib_event(nb, event, ptr);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return sw_nb_v6_fib_event(nb, event, ptr);
#endif
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_fib = {
	.notifier_call = sw_nb_fib_event,
};

static int sw_nb_net_event(struct notifier_block *nb,
			   unsigned long event, void *ptr)
{
	struct neighbour *n = ptr;

	if (!sw_nb_is_valid_dev(n->dev))
		return NOTIFY_DONE;

	if (event != NETEVENT_NEIGH_UPDATE)
		return NOTIFY_DONE;

	switch (n->tbl->family) {
	case AF_INET:
		return sw_nb_net_v4_neigh_update(nb, event, ptr);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return sw_nb_net_v6_neigh_update(nb, event, ptr);
#endif
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_netevent = {
	.notifier_call = sw_nb_net_event,

};

int sw_nb_inetaddr_event_to_otx2_event(int event, struct net_device *netdev)
{
	switch (event) {
	case NETDEV_CHANGE:
		return OTX2_DEV_CHANGE;
	case NETDEV_UP:
		return OTX2_DEV_UP;
	case NETDEV_DOWN:
		return OTX2_DEV_DOWN;
	default:
		break;
	}
	netdev_dbg(netdev, "%s: Wrong interaddr event %d\n",
		   __func__, event);
	return -1;
}

static struct notifier_block sw_nb_v4_inetaddr = {
	.notifier_call = sw_nb_v4_inetaddr_event,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct notifier_block sw_nb_v6_inetaddr = {
	.notifier_call = sw_nb_v6_inetaddr_event,
};
#endif

static int sw_nb_netdev_event(struct notifier_block *unused,
			      unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *idev;
	struct inet6_dev *i6dev;

	if (event != NETDEV_CHANGE &&
	    event != NETDEV_UP &&
	    event != NETDEV_DOWN) {
		return NOTIFY_DONE;
	}

	if (!sw_nb_is_valid_dev(dev))
		return NOTIFY_DONE;

	idev = __in_dev_get_rtnl(dev);
	if (idev)
		sw_nb_v4_netdev_event(unused, event, ptr);

	i6dev = __in6_dev_get(dev);
	if (i6dev)
		sw_nb_v6_netdev_event(unused, event, ptr);

	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_netdev = {
	.notifier_call = sw_nb_netdev_event,
};

int sw_nb_unregister(struct net_device *netdev)
{
	int err;

	err = unregister_switchdev_notifier(&sw_nb_fdb);

	if (err)
		netdev_err(netdev, "Failed to unregister switchdev nb\n");

	err = unregister_fib_notifier(&init_net, &sw_nb_fib);
	if (err)
		netdev_err(netdev, "Failed to unregister fib nb\n");

	err = unregister_netevent_notifier(&sw_nb_netevent);
	if (err)
		netdev_err(netdev, "Failed to unregister netevent\n");

	err = unregister_inetaddr_notifier(&sw_nb_v4_inetaddr);
	if (err)
		netdev_err(netdev, "Failed to unregister addr event\n");

#if IS_ENABLED(CONFIG_IPV6)
	err = unregister_inet6addr_notifier(&sw_nb_v6_inetaddr);
	if (err)
		netdev_err(netdev, "Failed to unregister addr event\n");
#endif

	err = unregister_netdevice_notifier(&sw_nb_netdev);
	if (err)
		netdev_err(netdev, "Failed to unregister netdev notifier\n");

	sw_fl_deinit();
	sw_fib_deinit();
	sw_fdb_deinit();

	sw_nb_pf_netdev = NULL;

	return 0;
}
EXPORT_SYMBOL(sw_nb_unregister);

int sw_nb_register(struct net_device *netdev)
{
	int err;

	sw_nb_pf_netdev = netdev;

	sw_fdb_init();
	sw_fib_init();
	sw_fl_init();

	err = register_switchdev_notifier(&sw_nb_fdb);
	if (err) {
		netdev_err(netdev, "Failed to register switchdev nb\n");
		sw_nb_pf_netdev = NULL;
		return err;
	}

	err = register_fib_notifier(&init_net, &sw_nb_fib, NULL, NULL);
	if (err) {
		netdev_err(netdev, "Failed to register fb notifier block\n");
		goto err1;
	}

	err = register_netevent_notifier(&sw_nb_netevent);
	if (err) {
		netdev_err(netdev, "Failed to register netevent\n");
		goto err2;
	}

#if IS_ENABLED(CONFIG_IPV6)
	err = register_inet6addr_notifier(&sw_nb_v6_inetaddr);
	if (err) {
		netdev_err(netdev, "Failed to register addr event\n");
		goto err3;
	}
#endif

	err = register_inetaddr_notifier(&sw_nb_v4_inetaddr);
	if (err) {
		netdev_err(netdev, "Failed to register addr event\n");
		goto err4;
	}

	err = register_netdevice_notifier(&sw_nb_netdev);
	if (err) {
		netdev_err(netdev, "Failed to register netdevice nb\n");
		goto err5;
	}

	return 0;

err5:
	unregister_inetaddr_notifier(&sw_nb_v4_inetaddr);

err4:
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&sw_nb_v6_inetaddr);

err3:
#endif
	unregister_netevent_notifier(&sw_nb_netevent);

err2:
	unregister_fib_notifier(&init_net, &sw_nb_fib);

err1:
	unregister_switchdev_notifier(&sw_nb_fdb);

	sw_fl_deinit();
	sw_fib_deinit();
	sw_fdb_deinit();

	sw_nb_pf_netdev = NULL;
	return err;
}
EXPORT_SYMBOL(sw_nb_register);
