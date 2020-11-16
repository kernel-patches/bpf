/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * ethtool.h: Defines for Linux ethtool.
 *
 * Copyright (C) 1998 David S. Miller (davem@redhat.com)
 * Copyright 2001 Jeff Garzik <jgarzik@pobox.com>
 * Portions Copyright 2001 Sun Microsystems (thockin@sun.com)
 * Portions Copyright 2002 Intel (eli.kupermann@intel.com,
 *                                christopher.leech@intel.com,
 *                                scott.feldman@intel.com)
 * Portions Copyright (C) Sun Microsystems 2008
 */

#ifndef _UAPI_LINUX_ETHTOOL_H
#define _UAPI_LINUX_ETHTOOL_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/if_ether.h>

#define ETHTOOL_GCHANNELS       0x0000003c /* Get no of channels */

/**
 * struct ethtool_channels - configuring number of network channel
 * @cmd: ETHTOOL_{G,S}CHANNELS
 * @max_rx: Read only. Maximum number of receive channel the driver support.
 * @max_tx: Read only. Maximum number of transmit channel the driver support.
 * @max_other: Read only. Maximum number of other channel the driver support.
 * @max_combined: Read only. Maximum number of combined channel the driver
 *	support. Set of queues RX, TX or other.
 * @rx_count: Valid values are in the range 1 to the max_rx.
 * @tx_count: Valid values are in the range 1 to the max_tx.
 * @other_count: Valid values are in the range 1 to the max_other.
 * @combined_count: Valid values are in the range 1 to the max_combined.
 *
 * This can be used to configure RX, TX and other channels.
 */

struct ethtool_channels {
	__u32	cmd;
	__u32	max_rx;
	__u32	max_tx;
	__u32	max_other;
	__u32	max_combined;
	__u32	rx_count;
	__u32	tx_count;
	__u32	other_count;
	__u32	combined_count;
};

#define ETH_GSTRING_LEN		32

/**
 * enum ethtool_stringset - string set ID
 * @ETH_SS_TEST: Self-test result names, for use with %ETHTOOL_TEST
 * @ETH_SS_STATS: Statistic names, for use with %ETHTOOL_GSTATS
 * @ETH_SS_PRIV_FLAGS: Driver private flag names, for use with
 *	%ETHTOOL_GPFLAGS and %ETHTOOL_SPFLAGS
 * @ETH_SS_NTUPLE_FILTERS: Previously used with %ETHTOOL_GRXNTUPLE;
 *	now deprecated
 * @ETH_SS_FEATURES: Device feature names
 * @ETH_SS_RSS_HASH_FUNCS: RSS hush function names
 * @ETH_SS_PHY_STATS: Statistic names, for use with %ETHTOOL_GPHYSTATS
 * @ETH_SS_PHY_TUNABLES: PHY tunable names
 * @ETH_SS_LINK_MODES: link mode names
 * @ETH_SS_MSG_CLASSES: debug message class names
 * @ETH_SS_WOL_MODES: wake-on-lan modes
 * @ETH_SS_SOF_TIMESTAMPING: SOF_TIMESTAMPING_* flags
 * @ETH_SS_TS_TX_TYPES: timestamping Tx types
 * @ETH_SS_TS_RX_FILTERS: timestamping Rx filters
 * @ETH_SS_UDP_TUNNEL_TYPES: UDP tunnel types
 */
enum ethtool_stringset {
	ETH_SS_TEST		= 0,
	ETH_SS_STATS,
	ETH_SS_PRIV_FLAGS,
	ETH_SS_NTUPLE_FILTERS,
	ETH_SS_FEATURES,
	ETH_SS_RSS_HASH_FUNCS,
	ETH_SS_TUNABLES,
	ETH_SS_PHY_STATS,
	ETH_SS_PHY_TUNABLES,
	ETH_SS_LINK_MODES,
	ETH_SS_MSG_CLASSES,
	ETH_SS_WOL_MODES,
	ETH_SS_SOF_TIMESTAMPING,
	ETH_SS_TS_TX_TYPES,
	ETH_SS_TS_RX_FILTERS,
	ETH_SS_UDP_TUNNEL_TYPES,

	/* add new constants above here */
	ETH_SS_COUNT
};

#endif /* _UAPI_LINUX_ETHTOOL_H */
