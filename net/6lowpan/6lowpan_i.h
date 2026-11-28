/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __6LOWPAN_I_H
#define __6LOWPAN_I_H

#include <linux/if_arp.h>
#include <linux/netdevice.h>

#include <net/6lowpan.h>

extern const struct ndisc_ops lowpan_ndisc_ops;

static inline bool lowpan_is_dev(const struct net_device *dev)
{
	return dev->type == ARPHRD_6LOWPAN &&
	       dev->ndisc_ops == &lowpan_ndisc_ops;
}

/* caller must ensure lowpan_is_dev(dev) is true */
static inline bool lowpan_is_ll(const struct net_device *dev,
				enum lowpan_lltypes lltype)
{
	return lowpan_dev(dev)->lltype == lltype;
}

int addrconf_ifid_802154_6lowpan(u8 *eui, struct net_device *dev);

#ifdef CONFIG_6LOWPAN_DEBUGFS
void lowpan_dev_debugfs_init(struct net_device *dev);
void lowpan_dev_debugfs_exit(struct net_device *dev);

void __init lowpan_debugfs_init(void);
void lowpan_debugfs_exit(void);
#else
static inline void lowpan_dev_debugfs_init(struct net_device *dev) { }
static inline void lowpan_dev_debugfs_exit(struct net_device *dev) { }

static inline void __init lowpan_debugfs_init(void) { }
static inline void lowpan_debugfs_exit(void) { }
#endif /* CONFIG_6LOWPAN_DEBUGFS */

#endif /* __6LOWPAN_I_H */
