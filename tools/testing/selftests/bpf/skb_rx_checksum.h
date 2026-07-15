/* SPDX-License-Identifier: GPL-2.0 */

enum skb_csum {
	SKB_CSUM_NONE		= 0,
	SKB_CSUM_UNNECESSARY	= 1,
	SKB_CSUM_COMPLETE	= 2,
	SKB_CSUM_PARTIAL	= 3,
};
