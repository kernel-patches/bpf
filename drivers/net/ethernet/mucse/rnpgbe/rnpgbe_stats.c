// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include <linux/ethtool.h>
#include <net/netdev_queues.h>

#include "rnpgbe.h"
#include "rnpgbe_stats.h"

struct rnpgbe_queue_stat {
	char name[ETH_GSTRING_LEN];
	unsigned int offset;
};

#define RNPGBE_QUEUE_STAT(_field) \
	{ #_field, offsetof(struct mucse_queue_stats, _field) }

static const struct rnpgbe_queue_stat rnpgbe_tx_queue_stats[] = {
	RNPGBE_QUEUE_STAT(dma_map_failures),
};

static void rnpgbe_get_queue_stats_rx(struct net_device *netdev, int idx,
				      struct netdev_queue_stats_rx *stats)
{
	struct mucse *mucse = netdev_priv(netdev);
	const struct mucse_queue_stats *queue;
	unsigned int start;

	queue = &mucse->rx_stats[idx];
	do {
		start = u64_stats_fetch_begin(&queue->syncp);
		stats->packets = queue->delivered_packets;
		stats->bytes = queue->delivered_bytes;
	} while (u64_stats_fetch_retry(&queue->syncp, start));
	stats->alloc_fail = atomic64_read(&queue->page_alloc_failures) +
			    atomic64_read(&queue->skb_alloc_failures);
}

static void rnpgbe_get_queue_stats_tx(struct net_device *netdev, int idx,
				      struct netdev_queue_stats_tx *stats)
{
	struct mucse *mucse = netdev_priv(netdev);
	const struct mucse_queue_stats *queue;
	unsigned int start;

	queue = &mucse->tx_stats[idx];
	do {
		start = u64_stats_fetch_begin(&queue->syncp);
		stats->packets = queue->packets;
		stats->bytes = queue->bytes;
	} while (u64_stats_fetch_retry(&queue->syncp, start));
}

static void rnpgbe_get_base_stats(struct net_device *netdev,
				  struct netdev_queue_stats_rx *rx,
				  struct netdev_queue_stats_tx *tx)
{
	rx->packets = 0;
	rx->bytes = 0;
	rx->alloc_fail = 0;
	tx->packets = 0;
	tx->bytes = 0;

	/* Queue counters persist across interface down/up. Include any queues
	 * outside the active range when reporting device totals.
	 */
	netdev_stat_queue_sum(netdev, netdev->real_num_rx_queues,
			      netdev->num_rx_queues, rx,
			      netdev->real_num_tx_queues,
			      netdev->num_tx_queues, tx);
}

const struct netdev_stat_ops rnpgbe_stat_ops = {
	.get_queue_stats_rx = rnpgbe_get_queue_stats_rx,
	.get_queue_stats_tx = rnpgbe_get_queue_stats_tx,
	.get_base_stats = rnpgbe_get_base_stats,
};

static void rnpgbe_read_stats(struct mucse *mucse)
{
	struct mucse_hw_stats *stats = &mucse->hw_stats;
	struct mucse_hw *hw = &mucse->hw;
	u32 value;
	int i;

	/* These 32-bit counters do not clear on read. Unsigned differences
	 * extend them across wraparound; hardware reset clears them.
	 */
	value = mucse_hw_rd32(hw, RNPGBE_ETH_RX_FCS_ERRORS);
	stats->rx_crc_errors += (u32)(value - stats->rx_crc_errors_prev);
	stats->rx_crc_errors_prev = value;

	for (i = 0; i < mucse->num_rx_queues; i++) {
		u32 index = mucse->rx_ring[i]->rnpgbe_queue_idx;

		value = mucse_hw_rd32(hw, RNPGBE_DMA_RX_MULTICAST(index));
		stats->multicast += (u32)(value - stats->multicast_prev[i]);
		stats->multicast_prev[i] = value;
	}
}

/**
 * rnpgbe_update_stats - Accumulate the hardware counters
 * @mucse: device private structure
 */
void rnpgbe_update_stats(struct mucse *mucse)
{
	spin_lock_bh(&mucse->hw_stats.lock);
	rnpgbe_read_stats(mucse);
	spin_unlock_bh(&mucse->hw_stats.lock);
}

/**
 * rnpgbe_init_stats - Initialize counter snapshots after the probe reset
 * @mucse: device private structure
 */
void rnpgbe_init_stats(struct mucse *mucse)
{
	struct mucse_hw_stats *stats = &mucse->hw_stats;
	struct mucse_hw *hw = &mucse->hw;
	int i;

	spin_lock_init(&stats->lock);

	stats->rx_crc_errors_prev = mucse_hw_rd32(hw, RNPGBE_ETH_RX_FCS_ERRORS);
	for (i = 0; i < mucse->num_rx_queues; i++) {
		u32 index = mucse->rx_ring[i]->rnpgbe_queue_idx;

		stats->multicast_prev[i] =
			mucse_hw_rd32(hw, RNPGBE_DMA_RX_MULTICAST(index));
	}
}

/**
 * rnpgbe_get_hw_stats - Add cached counters to the interface statistics
 * @mucse: device private structure
 * @stats: interface statistics to update
 */
void rnpgbe_get_hw_stats(struct mucse *mucse, struct rtnl_link_stats64 *stats)
{
	spin_lock_bh(&mucse->hw_stats.lock);
	stats->rx_crc_errors += mucse->hw_stats.rx_crc_errors;
	stats->rx_errors += mucse->hw_stats.rx_crc_errors;
	stats->multicast += mucse->hw_stats.multicast;
	spin_unlock_bh(&mucse->hw_stats.lock);
}

/**
 * rnpgbe_get_sset_count - Return the number of queue counters
 * @netdev: network interface
 * @sset: requested string set
 *
 * Return: counter count, or -EOPNOTSUPP for other string sets
 */
int rnpgbe_get_sset_count(struct net_device *netdev, int sset)
{
	struct mucse *mucse = netdev_priv(netdev);

	if (sset != ETH_SS_STATS)
		return -EOPNOTSUPP;

	return mucse->num_tx_queues * ARRAY_SIZE(rnpgbe_tx_queue_stats);
}

/**
 * rnpgbe_get_strings - Report the queue counter names
 * @netdev: network interface
 * @sset: requested string set
 * @data: buffer for fixed-width counter names
 */
void rnpgbe_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	struct mucse *mucse = netdev_priv(netdev);
	int i, j;

	if (sset != ETH_SS_STATS)
		return;

	for (i = 0; i < mucse->num_tx_queues; i++)
		for (j = 0; j < ARRAY_SIZE(rnpgbe_tx_queue_stats); j++)
			ethtool_sprintf(&data, "tx_queue_%u_%s", i,
					rnpgbe_tx_queue_stats[j].name);
}

static void rnpgbe_get_queue_stats(const struct mucse_queue_stats *queue,
				   const struct rnpgbe_queue_stat *table,
				   unsigned int count, u64 *data)
{
	int i;

	for (i = 0; i < count; i++) {
		const void *counter;

		counter = (const u8 *)queue + table[i].offset;
		data[i] = atomic64_read(counter);
	}
}

/**
 * rnpgbe_get_ethtool_stats - Report the queue counter values
 * @netdev: network interface
 * @stats: ethtool statistics request
 * @data: buffer for values in the order returned by rnpgbe_get_strings()
 */
void rnpgbe_get_ethtool_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct mucse *mucse = netdev_priv(netdev);
	int i;

	for (i = 0; i < mucse->num_tx_queues; i++) {
		rnpgbe_get_queue_stats(&mucse->tx_stats[i],
				       rnpgbe_tx_queue_stats,
				       ARRAY_SIZE(rnpgbe_tx_queue_stats), data);
		data += ARRAY_SIZE(rnpgbe_tx_queue_stats);
	}
}
