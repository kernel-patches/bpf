/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022, Intel Corporation. */

#ifndef __LINUX_NET_XDP_META_H__
#define __LINUX_NET_XDP_META_H__

#include <net/xdp.h>

/* Drivers not supporting XDP metadata can use this helper, which
 * rejects any room expansion for metadata as a result.
 */
static __always_inline void
xdp_set_data_meta_invalid(struct xdp_buff *xdp)
{
	xdp->data_meta = xdp->data + 1;
}

static __always_inline bool
xdp_data_meta_unsupported(const struct xdp_buff *xdp)
{
	return unlikely(xdp->data_meta > xdp->data);
}

static inline bool xdp_metalen_invalid(unsigned long metalen)
{
	return (metalen & (sizeof(__u32) - 1)) || (metalen > 32);
}

#endif /* __LINUX_NET_XDP_META_H__ */
