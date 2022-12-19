/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Network device xdp features.
 */
#ifndef _LINUX_XDP_FEATURES_H
#define _LINUX_XDP_FEATURES_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <asm/byteorder.h>
#include <uapi/linux/xdp_features.h>

typedef u32 xdp_features_t;

#define __XDP_F_BIT(bit)	((xdp_features_t)1 << (bit))
#define __XDP_F(name)		__XDP_F_BIT(XDP_F_##name##_BIT)

#define XDP_F_ABORTED		__XDP_F(ABORTED)
#define XDP_F_DROP		__XDP_F(DROP)
#define XDP_F_PASS		__XDP_F(PASS)
#define XDP_F_TX		__XDP_F(TX)
#define XDP_F_REDIRECT		__XDP_F(REDIRECT)
#define XDP_F_REDIRECT_TARGET	__XDP_F(REDIRECT_TARGET)
#define XDP_F_SOCK_ZEROCOPY	__XDP_F(SOCK_ZEROCOPY)
#define XDP_F_HW_OFFLOAD	__XDP_F(HW_OFFLOAD)
#define XDP_F_TX_LOCK		__XDP_F(TX_LOCK)
#define XDP_F_FRAG_RX		__XDP_F(FRAG_RX)
#define XDP_F_FRAG_TARGET	__XDP_F(FRAG_TARGET)

#define XDP_F_BASIC		(XDP_F_ABORTED | XDP_F_DROP |	\
				 XDP_F_PASS | XDP_F_TX)

#define XDP_F_FULL		(XDP_F_BASIC | XDP_F_REDIRECT)

#define XDP_F_FULL_ZC		(XDP_F_FULL | XDP_F_SOCK_ZEROCOPY)

#define XDP_FEATURES_ABORTED_STR		"xdp-aborted"
#define XDP_FEATURES_DROP_STR			"xdp-drop"
#define XDP_FEATURES_PASS_STR			"xdp-pass"
#define XDP_FEATURES_TX_STR			"xdp-tx"
#define XDP_FEATURES_REDIRECT_STR		"xdp-redirect"
#define XDP_FEATURES_REDIRECT_TARGET_STR	"xdp-redirect-target"
#define XDP_FEATURES_SOCK_ZEROCOPY_STR		"xdp-sock-zerocopy"
#define XDP_FEATURES_HW_OFFLOAD_STR		"xdp-hw-offload"
#define XDP_FEATURES_TX_LOCK_STR		"xdp-tx-lock"
#define XDP_FEATURES_FRAG_RX_STR		"xdp-frag-rx"
#define XDP_FEATURES_FRAG_TARGET_STR		"xdp-frag-target"

#define DECLARE_XDP_FEATURES_TABLE(name, length)				\
	const char name[][length] = {						\
		[XDP_F_ABORTED_BIT] = XDP_FEATURES_ABORTED_STR,			\
		[XDP_F_DROP_BIT] = XDP_FEATURES_DROP_STR,			\
		[XDP_F_PASS_BIT] = XDP_FEATURES_PASS_STR,			\
		[XDP_F_TX_BIT] = XDP_FEATURES_TX_STR,				\
		[XDP_F_REDIRECT_BIT] = XDP_FEATURES_REDIRECT_STR,		\
		[XDP_F_REDIRECT_TARGET_BIT] = XDP_FEATURES_REDIRECT_TARGET_STR,	\
		[XDP_F_SOCK_ZEROCOPY_BIT] = XDP_FEATURES_SOCK_ZEROCOPY_STR,	\
		[XDP_F_HW_OFFLOAD_BIT] = XDP_FEATURES_HW_OFFLOAD_STR,		\
		[XDP_F_TX_LOCK_BIT] = XDP_FEATURES_TX_LOCK_STR,			\
		[XDP_F_FRAG_RX_BIT] = XDP_FEATURES_FRAG_RX_STR,			\
		[XDP_F_FRAG_TARGET_BIT] = XDP_FEATURES_FRAG_TARGET_STR,		\
	}

#endif /* _LINUX_XDP_FEATURES_H */
