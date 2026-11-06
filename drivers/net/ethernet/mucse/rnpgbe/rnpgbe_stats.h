/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#ifndef _RNPGBE_STATS_H
#define _RNPGBE_STATS_H

#include <linux/spinlock.h>
#include <linux/types.h>

#include "rnpgbe_hw.h"

struct ethtool_stats;
struct net_device;
struct netdev_stat_ops;
struct rtnl_link_stats64;
struct mucse;

struct mucse_hw_stats {
	/* Protects the hardware snapshots and software totals. */
	spinlock_t lock;
	u64 rx_crc_errors;
	u64 multicast;
	u32 rx_crc_errors_prev;
	u32 multicast_prev[RNPGBE_MAX_QUEUES];
};

extern const struct netdev_stat_ops rnpgbe_stat_ops;

void rnpgbe_init_stats(struct mucse *mucse);
void rnpgbe_update_stats(struct mucse *mucse);
void rnpgbe_get_hw_stats(struct mucse *mucse, struct rtnl_link_stats64 *stats);
int rnpgbe_get_sset_count(struct net_device *netdev, int sset);
void rnpgbe_get_strings(struct net_device *netdev, u32 sset, u8 *data);
void rnpgbe_get_ethtool_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data);

#endif /* _RNPGBE_STATS_H */
