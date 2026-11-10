/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef XDP_PACKET_HEADROOM
#define XDP_PACKET_HEADROOM 256
#endif

/* Metadata in BPF_PROG_RUN must be this size or smaller */
#define MAX_META_LEN (XDP_PACKET_HEADROOM - (int)sizeof(struct xdp_frame))

#define SKB_MAX_CSUM_LEVEL 3

#ifndef BIT
#define BIT(nr)			(1 << (nr))
#endif

enum xdp_skb_ext_field {
	SKB_EXT_FIELD_HASH = BIT(0),
	SKB_EXT_FIELD_VLAN = BIT(1),
	SKB_EXT_FIELD_CSUM = BIT(2),
};

enum xdp_skb_ext_deliver {
	DELIVER_PASS,
	DELIVER_CPUMAP,
	DELIVER_VETH,
};

/* The entries that the XDP programs store or load */
struct xdp_skb_ext_vals {
	__u32 rx_hash;
	__u32 rx_hash_type;
	__be16 rx_vlan_proto;
	__u16 rx_vlan_tci;
	__u32 ip_summed;
	__u8 csum_level;
	enum xdp_skb_ext_field fields;
};

/* The skb fields that the tc program reads */
struct xdp_skb_ext_have {
	__u32 hash;
	__u32 l4_hash;
	__u32 vlan_present;
	__u32 vlan_proto;
	__u32 vlan_tci;
	__u32 ip_summed;
	__u32 csum_level;
};
