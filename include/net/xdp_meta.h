/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022, Intel Corporation. */

#ifndef __LINUX_NET_XDP_META_H__
#define __LINUX_NET_XDP_META_H__

#include <net/xdp.h>
#include <uapi/linux/bpf.h>

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

/**
 * xdp_metalen_invalid -- check if the length of a frame's metadata is valid
 * @metalen: the length of the frame's metadata
 *
 * skb_shared_info::meta_len is of 1 byte long, thus it can't be longer than
 * 255, but this always can change. XDP_PACKET_HEADROOM is 256, and this is a
 * UAPI. sizeof(struct xdp_frame) is reserved since xdp_frame is being placed
 * at xdp_buff::data_hard_start whilst being constructed on XDP_REDIRECT.
 * The 32-bit alignment requirement is arbitrary, kept for simplicity and,
 * sometimes, speed.
 */
static inline bool xdp_metalen_invalid(unsigned long metalen)
{
	typeof(metalen) max;

	max = min_t(typeof(max),
		    (typeof_member(struct skb_shared_info, meta_len))~0UL,
		    XDP_PACKET_HEADROOM - sizeof(struct xdp_frame));
	BUILD_BUG_ON(!__builtin_constant_p(max));

	return (metalen & (sizeof(u32) - 1)) || metalen > max;
}

#endif /* __LINUX_NET_XDP_META_H__ */
