/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef _BPF_NETPOLL_H
#define _BPF_NETPOLL_H

#include <linux/types.h>

#define BPF_NETPOLL_DEV_NAME_LEN 16	/* IFNAMSIZ */

/**
 * struct bpf_netpoll_opts - BPF netpoll initialization parameters
 * @dev_name:	Network device name (e.g. "eth0"), null-terminated.
 * @local_ip:	Local IPv4 address in network byte order. 0 = auto-detect.
 * @remote_ip:	Remote IPv4 address in network byte order.
 * @local_port:	Local UDP port in host byte order.
 * @remote_port: Remote UDP port in host byte order.
 * @remote_mac:	Remote MAC address (6 bytes).
 * @ipv6:	Set to 1 for IPv6, 0 for IPv4.
 * @reserved:	Must be zero. Reserved for future use.
 * @local_ip6:	Local IPv6 address (16 bytes). Used when ipv6=1.
 *		Zero = auto-detect.
 * @remote_ip6:	Remote IPv6 address (16 bytes). Used when ipv6=1.
 */
struct bpf_netpoll_opts {
	char dev_name[BPF_NETPOLL_DEV_NAME_LEN];
	__be32 local_ip;
	__be32 remote_ip;
	__u16 local_port;
	__u16 remote_port;
	__u8 remote_mac[6];
	__u8 ipv6;
	__u8 reserved;
	__u8 local_ip6[16];
	__u8 remote_ip6[16];
};

#endif /* _BPF_NETPOLL_H */
