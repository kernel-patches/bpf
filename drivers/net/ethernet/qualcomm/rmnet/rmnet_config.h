/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2013-2014, 2016-2018, 2021 The Linux Foundation.
 * All rights reserved.
 *
 * RMNET Data configuration engine
 */

#include <linux/skbuff.h>
#include <linux/time.h>
#include <net/gro_cells.h>

#ifndef _RMNET_CONFIG_H_
#define _RMNET_CONFIG_H_

#define RMNET_MAX_LOGICAL_EP 255

struct rmnet_endpoint {
	u8 mux_id;
	struct net_device *egress_dev;
	struct hlist_node hlnode;
	struct rcu_head rcu;
};

struct rmnet_egress_agg_params {
	u32 bytes;
	u32 count;
	u64 time_nsec;
};

/* One instance of this structure is instantiated for each real_dev associated
 * with rmnet.
 */
struct rmnet_port {
	struct net_device *dev;
	u32 data_format;
	u8 nr_rmnet_devs;
	u8 rmnet_mode;
	struct hlist_head muxed_ep[RMNET_MAX_LOGICAL_EP];
	struct net_device *bridge_ep;
	struct net_device *rmnet_dev;

	/* Egress aggregation information */
	struct rmnet_egress_agg_params egress_agg_params;
	/* Protect aggregation related elements */
	spinlock_t agg_lock;
	struct sk_buff *skbagg_head;
	struct sk_buff *skbagg_tail;
	int agg_state;
	u8 agg_count;
	struct timespec64 agg_time;
	struct timespec64 agg_last;
	struct hrtimer hrtimer;
	struct work_struct agg_wq;
};

extern struct rtnl_link_ops rmnet_link_ops;

struct rmnet_vnd_stats {
	u64 rx_pkts;
	u64 rx_bytes;
	u64 tx_pkts;
	u64 tx_bytes;
	u32 tx_drops;
};

struct rmnet_priv_stats {
	/* Network stack RX statistics for all rmnet receive paths */
	u64 rx_hw_gro_packets;
	u64 rx_hw_gro_wire_packets;
	u64 rx_alloc_fail;
	u64 rx_dropped;

	/* Custom diagnostics for the coalescing receive path */
	struct_group(ethtool_stats, /* ethtool statistics */
		u64 csum_ok;
		u64 csum_ip4_header_bad;
		u64 csum_valid_unset;
		u64 csum_validation_failed;
		u64 csum_err_bad_buffer;
		u64 csum_err_invalid_ip_version;
		u64 csum_err_invalid_transport;
		u64 csum_fragmented_pkt;
		u64 csum_skipped;
		u64 csum_sw;
		u64 csum_hw;
		/* Coalescing-only counters. Some are subsets of the standard counters. */
		u64 coal_alloc_fail;
		u64 coal_rx;
		u64 coal_pkts;
		u64 coal_hdr_err;
		u64 coal_hdr_pkt_err;
		u64 coal_bounds_err;
		u64 coal_csum_err;
		u64 coal_csum_drop;
		u64 coal_reconstruct;
		u64 coal_ip_invalid;
		u64 coal_trans_invalid;
		/* close-reason sub-counters */
		u64 coal_close_non_coal;
		u64 coal_close_ip_miss;
		u64 coal_close_trans_miss;
		u64 coal_close_hw_nl;
		u64 coal_close_hw_pkt;
		u64 coal_close_hw_byte;
		u64 coal_close_hw_time;
		u64 coal_close_hw_evict;
		u64 coal_close_coal;
	);
};

struct rmnet_pcpu_priv_stats {
	/* Network stack RX statistics for all rmnet receive paths */
	u64_stats_t rx_hw_gro_packets;
	u64_stats_t rx_hw_gro_wire_packets;
	u64_stats_t rx_alloc_fail;
	u64_stats_t rx_dropped;

	/* Custom diagnostics for the coalescing receive path */
	u64_stats_t csum_ok;
	u64_stats_t csum_ip4_header_bad;
	u64_stats_t csum_valid_unset;
	u64_stats_t csum_validation_failed;
	u64_stats_t csum_err_bad_buffer;
	u64_stats_t csum_err_invalid_ip_version;
	u64_stats_t csum_err_invalid_transport;
	u64_stats_t csum_fragmented_pkt;
	u64_stats_t csum_skipped;
	u64_stats_t csum_sw;
	u64_stats_t csum_hw;
	/* Coalescing-only counters. Some are subsets of the standard counters. */
	u64_stats_t coal_alloc_fail;
	u64_stats_t coal_rx;
	u64_stats_t coal_pkts;
	u64_stats_t coal_hdr_err;
	u64_stats_t coal_hdr_pkt_err;
	u64_stats_t coal_bounds_err;
	u64_stats_t coal_csum_err;
	u64_stats_t coal_csum_drop;
	u64_stats_t coal_reconstruct;
	u64_stats_t coal_ip_invalid;
	u64_stats_t coal_trans_invalid;
	/* close-reason sub-counters */
	u64_stats_t coal_close_non_coal;
	u64_stats_t coal_close_ip_miss;
	u64_stats_t coal_close_trans_miss;
	u64_stats_t coal_close_hw_nl;
	u64_stats_t coal_close_hw_pkt;
	u64_stats_t coal_close_hw_byte;
	u64_stats_t coal_close_hw_time;
	u64_stats_t coal_close_hw_evict;
	u64_stats_t coal_close_coal;
};

struct rmnet_pcpu_stats {
	struct rmnet_vnd_stats stats;
	struct rmnet_pcpu_priv_stats priv_stats;
	struct u64_stats_sync syncp;
};

struct rmnet_priv {
	u8 mux_id;
	struct net_device *real_dev;
	struct rmnet_pcpu_stats __percpu *pcpu_stats;
	struct gro_cells gro_cells;
};

struct rmnet_port *rmnet_get_port_rcu(const struct net_device *real_dev);
struct rmnet_endpoint *rmnet_get_endpoint(struct rmnet_port *port, u8 mux_id);
int rmnet_add_bridge(struct net_device *rmnet_dev,
		     struct net_device *slave_dev,
		     struct netlink_ext_ack *extack);
int rmnet_del_bridge(struct net_device *rmnet_dev,
		     struct net_device *slave_dev);
struct rmnet_port*
rmnet_get_port_rtnl(const struct net_device *real_dev);
#endif /* _RMNET_CONFIG_H_ */
