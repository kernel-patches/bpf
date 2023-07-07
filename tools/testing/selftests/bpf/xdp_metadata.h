/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

struct xdp_meta {
	__u64 rx_timestamp;
	__u64 xdp_timestamp;
	__u32 rx_hash;
	union {
		__u32 rx_hash_type;
		__s32 rx_hash_err;
	};
};

struct devtx_sample {
	int timestamp_retval;
	__u64 hw_timestamp;
	__u64 sw_complete_timestamp;
	__u16 tx_csum;
};

#define TX_META_LEN	8

struct xdp_tx_meta {
	__u8 request_timestamp;
	__u8 padding0;
	__u16 padding1;
	__u32 padding2;
};
