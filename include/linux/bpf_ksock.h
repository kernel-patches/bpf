/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Isovalent */

#ifndef _BPF_KSOCK_H
#define _BPF_KSOCK_H

#include <linux/types.h>

/**
 * struct bpf_ksock_create_opts - BPF kernel socket creation parameters
 * @family:	Address family: AF_INET or AF_INET6.
 * @type:	Socket type: only SOCK_DGRAM supported for now.
 * @protocol:	Protocol number (e.g. IPPROTO_UDP), or 0 for the default protocol
 *		of the given type.
 * @reserved:	Must be zero. Reserved for future use.
 */
struct bpf_ksock_create_opts {
	__u8 family;
	__u8 type;
	__u8 protocol;
	__u8 reserved;
};

/**
 * struct bpf_ksock_addr_opts - BPF kernel socket address parameters
 * @family:	Address family: AF_INET or AF_INET6.
 * @reserved:	Must be zero. Reserved for future use.
 * @port:	Port in host byte order.
 * @scope_id:	IPv6 scope ID for scoped AF_INET6 addresses, or zero.
 *		Must be zero when family=AF_INET.
 * @ipv4_addr:	IPv4 address in network byte order. Used when family=AF_INET.
 * @ipv6_addr:	IPv6 address (16 bytes, network byte order). Used when family=AF_INET6.
 */
struct bpf_ksock_addr_opts {
	__u8 family;
	__u8 reserved;
	__u16 port;
	__u32 scope_id;

	union {
		__be32 ipv4_addr;
		__u32 ipv6_addr[4]; /* in6_addr; network order */
	};
};

#endif /* _BPF_KSOCK_H */
