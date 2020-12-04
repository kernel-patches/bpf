/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Network device xdp properties.
 */
#ifndef _LINUX_XDP_PROPERTIES_H
#define _LINUX_XDP_PROPERTIES_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <asm/byteorder.h>

typedef u64 xdp_properties_t;

enum {
	XDP_F_ABORTED_BIT,
	XDP_F_DROP_BIT,
	XDP_F_PASS_BIT,
	XDP_F_TX_BIT,
	XDP_F_REDIRECT_BIT,
	XDP_F_ZEROCOPY_BIT,
	XDP_F_HW_OFFLOAD_BIT,

	/*
	 * Add your fresh new property above and remember to update
	 * xdp_properties_strings [] in net/core/ethtool.c and maybe
	 * some xdp_properties mask #defines below. Please also describe it
	 * in Documentation/networking/xdp_properties.rst.
	 */

	/**/XDP_PROPERTIES_COUNT
};

#define __XDP_F_BIT(bit)	((xdp_properties_t)1 << (bit))
#define __XDP_F(name)		__XDP_F_BIT(XDP_F_##name##_BIT)

#define XDP_F_ABORTED		__XDP_F(ABORTED)
#define XDP_F_DROP		__XDP_F(DROP)
#define XDP_F_PASS		__XDP_F(PASS)
#define XDP_F_TX		__XDP_F(TX)
#define XDP_F_REDIRECT		__XDP_F(REDIRECT)
#define XDP_F_ZEROCOPY		__XDP_F(ZEROCOPY)
#define XDP_F_HW_OFFLOAD	__XDP_F(HW_OFFLOAD)

#define XDP_F_BASIC		(XDP_F_ABORTED |	\
				 XDP_F_DROP |		\
				 XDP_F_PASS |		\
				 XDP_F_TX)

#define XDP_F_FULL		(XDP_F_BASIC | XDP_F_REDIRECT)

#define XDP_F_FULL_ZC		(XDP_F_FULL | XDP_F_ZEROCOPY)

#endif /* _LINUX_XDP_PROPERTIES_H */
