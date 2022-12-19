/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2020 Intel
 */

#ifndef __UAPI_LINUX_XDP_FEATURES__
#define __UAPI_LINUX_XDP_FEATURES__

enum {
	XDP_F_ABORTED_BIT,
	XDP_F_DROP_BIT,
	XDP_F_PASS_BIT,
	XDP_F_TX_BIT,
	XDP_F_REDIRECT_BIT,
	XDP_F_REDIRECT_TARGET_BIT,
	XDP_F_SOCK_ZEROCOPY_BIT,
	XDP_F_HW_OFFLOAD_BIT,
	XDP_F_TX_LOCK_BIT,
	XDP_F_FRAG_RX_BIT,
	XDP_F_FRAG_TARGET_BIT,
	/*
	 * Add your fresh new property above and remember to update
	 * documentation.
	 */
	XDP_FEATURES_COUNT,
};

#define XDP_FEATURES_WORDS			((XDP_FEATURES_COUNT + 32 - 1) / 32)
#define XDP_FEATURES_WORD(blocks, index)	((blocks)[(index) / 32U])
#define XDP_FEATURES_FIELD_FLAG(index)		(1U << (index) % 32U)
#define XDP_FEATURES_BIT_IS_SET(blocks, index)        \
	(XDP_FEATURES_WORD(blocks, index) & XDP_FEATURES_FIELD_FLAG(index))

#endif  /* __UAPI_LINUX_XDP_FEATURES__ */
