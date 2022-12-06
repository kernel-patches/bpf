/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

struct xdp_meta {
	__u64 rx_timestamp;
	__u32 rx_hash;
};
