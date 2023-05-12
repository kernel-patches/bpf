/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define BIT(nr)			(1 << (nr))

enum xdp_meta_field {
	XDP_META_FIELD_TS	= BIT(0),
	XDP_META_FIELD_RSS	= BIT(1),
	XDP_META_FIELD_CTAG	= BIT(2),
	XDP_META_FIELD_STAG	= BIT(3),
	XDP_META_FIELD_CSUM_LVL	= BIT(4),
};

struct xdp_meta {
	union {
		__u64 rx_timestamp;
		__s32 rx_timestamp_err;
	};
	__u64 xdp_timestamp;
	__u32 rx_hash;
	union {
		__u32 rx_hash_type;
		__s32 rx_hash_err;
	};
	union {
		__u16 rx_ctag;
		__s32 rx_ctag_err;
	};
	union {
		__u16 rx_stag;
		__s32 rx_stag_err;
	};
	union {
		__u8 rx_csum_lvl;
		__s32 rx_csum_err;
	};
	enum xdp_meta_field hint_valid;
};
