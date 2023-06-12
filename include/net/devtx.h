/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_NET_DEVTX_H__
#define __LINUX_NET_DEVTX_H__

#include <linux/jump_label.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/xdp.h>

struct devtx_frame {
	void *data;
	u16 len;
	struct skb_shared_info *sinfo; /* for frags */
};

#ifdef CONFIG_NET
void devtx_submit(struct net_device *netdev, struct devtx_frame *ctx);
void devtx_complete(struct net_device *netdev, struct devtx_frame *ctx);
bool is_devtx_kfunc(u32 kfunc_id);
void devtx_shutdown(struct net_device *netdev);

static inline void devtx_frame_from_skb(struct devtx_frame *ctx, struct sk_buff *skb)
{
	ctx->data = skb->data;
	ctx->len = skb_headlen(skb);
	ctx->sinfo = skb_shinfo(skb);
}

static inline void devtx_frame_from_xdp(struct devtx_frame *ctx, struct xdp_frame *xdpf)
{
	ctx->data = xdpf->data;
	ctx->len = xdpf->len;
	ctx->sinfo = xdp_frame_has_frags(xdpf) ? xdp_get_shared_info_from_frame(xdpf) : NULL;
}

DECLARE_STATIC_KEY_FALSE(devtx_enabled);

static inline bool devtx_submit_enabled(struct net_device *netdev)
{
	return static_branch_unlikely(&devtx_enabled) &&
	       rcu_access_pointer(netdev->devtx_sb);
}

static inline bool devtx_complete_enabled(struct net_device *netdev)
{
	return static_branch_unlikely(&devtx_enabled) &&
	       rcu_access_pointer(netdev->devtx_cp);
}
#else
static inline void devtx_submit(struct net_device *netdev, struct devtx_frame *ctx)
{
}

static inline void devtx_complete(struct net_device *netdev, struct devtx_frame *ctx)
{
}

static inline bool is_devtx_kfunc(u32 kfunc_id)
{
	return false;
}

static inline void devtx_shutdown(struct net_device *netdev)
{
}

static inline void devtx_frame_from_skb(struct devtx_frame *ctx, struct sk_buff *skb)
{
}

static inline void devtx_frame_from_xdp(struct devtx_frame *ctx, struct xdp_frame *xdpf)
{
}
#endif

#endif /* __LINUX_NET_DEVTX_H__ */
