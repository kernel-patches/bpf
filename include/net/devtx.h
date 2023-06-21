/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_NET_DEVTX_H__
#define __LINUX_NET_DEVTX_H__

#include <linux/jump_label.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/btf_ids.h>
#include <net/xdp.h>

struct devtx_frame {
	void *data;
	u16 len;
	u8 meta_len;
	struct skb_shared_info *sinfo; /* for frags */
	struct net_device *netdev;
};

#ifdef CONFIG_NET
void devtx_hooks_enable(void);
void devtx_hooks_disable(void);
bool devtx_hooks_match(u32 attach_btf_id, const struct xdp_metadata_ops *xmo);
int devtx_hooks_register(struct btf_id_set8 *set, const struct xdp_metadata_ops *xmo);
void devtx_hooks_unregister(struct btf_id_set8 *set);

static inline void devtx_frame_from_skb(struct devtx_frame *ctx, struct sk_buff *skb,
					struct net_device *netdev)
{
	ctx->data = skb->data;
	ctx->len = skb_headlen(skb);
	ctx->meta_len = skb_metadata_len(skb);
	ctx->sinfo = skb_shinfo(skb);
	ctx->netdev = netdev;
}

static inline void devtx_frame_from_xdp(struct devtx_frame *ctx, struct xdp_frame *xdpf,
					struct net_device *netdev)
{
	ctx->data = xdpf->data;
	ctx->len = xdpf->len;
	ctx->meta_len = xdpf->metasize & 0xff;
	ctx->sinfo = xdp_frame_has_frags(xdpf) ? xdp_get_shared_info_from_frame(xdpf) : NULL;
	ctx->netdev = netdev;
}

DECLARE_STATIC_KEY_FALSE(devtx_enabled_key);

static inline bool devtx_enabled(void)
{
	return static_branch_unlikely(&devtx_enabled_key);
}
#else
static inline void devtx_hooks_enable(void) {}
static inline void devtx_hooks_disable(void) {}
static inline bool devtx_hooks_match(u32 attach_btf_id, const struct xdp_metadata_ops *xmo) {}
static inline int devtx_hooks_register(struct btf_id_set8 *set,
				       const struct xdp_metadata_ops *xmo) {}
static inline void devtx_hooks_unregister(struct btf_id_set8 *set) {}

static inline void devtx_frame_from_skb(struct devtx_frame *ctx, struct sk_buff *skb,
					struct net_device *netdev) {}
static inline void devtx_frame_from_xdp(struct devtx_frame *ctx, struct xdp_frame *xdpf,
					struct net_device *netdev) {}

static inline bool devtx_enabled(void)
{
	return false;
}
#endif

#endif /* __LINUX_NET_DEVTX_H__ */
