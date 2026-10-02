/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XDP_LRU_WINDOW_H
#define __XDP_LRU_WINDOW_H

/*
 * ABI for the XDP LRU rolling-window selftest. Existing test_lru_map
 * coverage never enters XDP; XDP parse tests do not store a modulo
 * index into an LRU map value.
 */

#define AGGREGATION_WINDOW	50
#define XDP_LRU_WINDOW_FLOWS	64

struct xdp_lru_window_key {
	__be32	saddr;
	__be32	daddr;
	__be16	sport;
	__be16	dport;
	__u8	proto;
	__u8	pad[3];
};

struct xdp_lru_window_state {
	__u32	seq;
	__u32	pkt_len[AGGREGATION_WINDOW];
};

#endif /* __XDP_LRU_WINDOW_H */
