/* SPDX-License-Identifier: GPL-2.0 */

struct xsk_metadata {
	__u32 rx_timestamp_supported:1;
	__u64 rx_timestamp;
};
