/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_NET_DEVTX_H__
#define __LINUX_NET_DEVTX_H__

#include <linux/jump_label.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/btf_ids.h>
#include <net/xdp.h>

struct devtx_ctx {
	struct net_device *netdev;
	struct skb_shared_info *sinfo; /* for frags */
};

#define DECLARE_DEVTX_HOOKS(PREFIX) \
void PREFIX ## _devtx_submit_skb(struct devtx_ctx *ctx, struct sk_buff *skb); \
void PREFIX ## _devtx_complete_skb(struct devtx_ctx *ctx, struct sk_buff *skb); \
void PREFIX ## _devtx_submit_xdp(struct devtx_ctx *ctx, struct xdp_frame *xdpf); \
void PREFIX ## _devtx_complete_xdp(struct devtx_ctx *ctx, struct xdp_frame *xdpf)

#define DEFINE_DEVTX_HOOKS(PREFIX) \
__weak noinline void PREFIX ## _devtx_submit_skb(struct devtx_ctx *ctx, \
						 struct sk_buff *skb) {} \
__weak noinline void PREFIX ## _devtx_complete_skb(struct devtx_ctx *ctx, \
						   struct sk_buff *skb) {} \
__weak noinline void PREFIX ## _devtx_submit_xdp(struct devtx_ctx *ctx, \
						 struct xdp_frame *xdpf) {} \
__weak noinline void PREFIX ## _devtx_complete_xdp(struct devtx_ctx *ctx, \
						   struct xdp_frame *xdpf) {} \
\
BTF_SET8_START(PREFIX ## _devtx_hook_ids) \
BTF_ID_FLAGS(func, PREFIX ## _devtx_submit_skb) \
BTF_ID_FLAGS(func, PREFIX ## _devtx_complete_skb) \
BTF_ID_FLAGS(func, PREFIX ## _devtx_submit_xdp) \
BTF_ID_FLAGS(func, PREFIX ## _devtx_complete_xdp) \
BTF_SET8_END(PREFIX ## _devtx_hook_ids)

#ifdef CONFIG_NET
void devtx_hooks_enable(void);
void devtx_hooks_disable(void);
bool devtx_hooks_match(u32 attach_btf_id, const struct xdp_metadata_ops *xmo);
int devtx_hooks_register(struct btf_id_set8 *set, const struct xdp_metadata_ops *xmo);
void devtx_hooks_unregister(struct btf_id_set8 *set);

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

static inline bool devtx_enabled(void)
{
	return false;
}
#endif

#endif /* __LINUX_NET_DEVTX_H__ */
