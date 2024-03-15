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

#define ETHTOOL_FWVERS_LEN	32
#define ETHTOOL_BUSINFO_LEN	32
#define ETHTOOL_EROMVERS_LEN	32

/**
 * struct ethtool_drvinfo - general driver and device information
 * @cmd: Command number = %ETHTOOL_GDRVINFO
 * @driver: Driver short name.  This should normally match the name
 *	in its bus driver structure (e.g. pci_driver::name).  Must
 *	not be an empty string.
 * @version: Driver version string; may be an empty string
 * @fw_version: Firmware version string; may be an empty string
 * @erom_version: Expansion ROM version string; may be an empty string
 * @bus_info: Device bus address.  This should match the dev_name()
 *	string for the underlying bus device, if there is one.  May be
 *	an empty string.
 * @reserved2: Reserved for future use; see the note on reserved space.
 * @n_priv_flags: Number of flags valid for %ETHTOOL_GPFLAGS and
 *	%ETHTOOL_SPFLAGS commands; also the number of strings in the
 *	%ETH_SS_PRIV_FLAGS set
 * @n_stats: Number of u64 statistics returned by the %ETHTOOL_GSTATS
 *	command; also the number of strings in the %ETH_SS_STATS set
 * @testinfo_len: Number of results returned by the %ETHTOOL_TEST
 *	command; also the number of strings in the %ETH_SS_TEST set
 * @eedump_len: Size of EEPROM accessible through the %ETHTOOL_GEEPROM
 *	and %ETHTOOL_SEEPROM commands, in bytes
 * @regdump_len: Size of register dump returned by the %ETHTOOL_GREGS
 *	command, in bytes
 *
 * Users can use the %ETHTOOL_GSSET_INFO command to get the number of
 * strings in any string set (from Linux 2.6.34).
 *
 * Drivers should set at most @driver, @version, @fw_version and
 * @bus_info in their get_drvinfo() implementation.  The ethtool
 * core fills in the other fields using other driver operations.
 */
struct ethtool_drvinfo {
	__u32	cmd;
	char	driver[32];
	char	version[32];
	char	fw_version[ETHTOOL_FWVERS_LEN];
	char	bus_info[ETHTOOL_BUSINFO_LEN];
	char	erom_version[ETHTOOL_EROMVERS_LEN];
	char	reserved2[12];
	__u32	n_priv_flags;
	__u32	n_stats;
	__u32	testinfo_len;
	__u32	eedump_len;
	__u32	regdump_len;
};

#define ETHTOOL_GDRVINFO	0x00000003

/**
 * struct ethtool_ringparam - RX/TX ring parameters
 * @cmd: Command number = %ETHTOOL_GRINGPARAM or %ETHTOOL_SRINGPARAM
 * @rx_max_pending: Maximum supported number of pending entries per
 *      RX ring.  Read-only.
 * @rx_mini_max_pending: Maximum supported number of pending entries
 *      per RX mini ring.  Read-only.
 * @rx_jumbo_max_pending: Maximum supported number of pending entries
 *      per RX jumbo ring.  Read-only.
 * @tx_max_pending: Maximum supported number of pending entries per
 *      TX ring.  Read-only.
 * @rx_pending: Current maximum number of pending entries per RX ring
 * @rx_mini_pending: Current maximum number of pending entries per RX
 *      mini ring
 * @rx_jumbo_pending: Current maximum number of pending entries per RX
 *      jumbo ring
 * @tx_pending: Current maximum supported number of pending entries
 *      per TX ring
 *
 * If the interface does not have separate RX mini and/or jumbo rings,
 * @rx_mini_max_pending and/or @rx_jumbo_max_pending will be 0.
 *
 * There may also be driver-dependent minimum values for the number
 * of entries per ring.
 */

struct ethtool_ringparam {
	__u32   cmd;
	__u32   rx_max_pending;
	__u32   rx_mini_max_pending;
	__u32   rx_jumbo_max_pending;
	__u32   tx_max_pending;
	__u32   rx_pending;
	__u32   rx_mini_pending;
	__u32   rx_jumbo_pending;
	__u32   tx_pending;
};

#define ETHTOOL_GRINGPARAM      0x00000010 /* Get ring parameters. */
#define ETHTOOL_SRINGPARAM      0x00000011 /* Set ring parameters. */

#endif /* _UAPI_LINUX_ETHTOOL_H */
