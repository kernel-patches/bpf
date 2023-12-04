// SPDX-License-Identifier: GPL-2.0-only
/* Unstable XFRM BPF helpers.
 *
 * Note that it is allowed to break compatibility for these functions since the
 * interface they are exposed through to BPF programs is explicitly unstable.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <net/dst_metadata.h>
#include <net/xdp.h>
#include <net/xfrm.h>

#if IS_BUILTIN(CONFIG_XFRM_INTERFACE) || \
    (IS_MODULE(CONFIG_XFRM_INTERFACE) && IS_ENABLED(CONFIG_DEBUG_INFO_BTF_MODULES))

/* bpf_xfrm_info - XFRM metadata information
 *
 * Members:
 * @if_id	- XFRM if_id:
 *		    Transmit: if_id to be used in policy and state lookups
 *		    Receive: if_id of the state matched for the incoming packet
 * @link	- Underlying device ifindex:
 *		    Transmit: used as the underlying device in VRF routing
 *		    Receive: the device on which the packet had been received
 */
struct bpf_xfrm_info {
	u32 if_id;
	int link;
};

__bpf_kfunc_start_defs();

/* bpf_skb_get_xfrm_info - Get XFRM metadata
 *
 * Parameters:
 * @skb_ctx	- Pointer to ctx (__sk_buff) in TC program
 *		    Cannot be NULL
 * @to		- Pointer to memory to which the metadata will be copied
 *		    Cannot be NULL
 */
__bpf_kfunc int bpf_skb_get_xfrm_info(struct __sk_buff *skb_ctx, struct bpf_xfrm_info *to)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct xfrm_md_info *info;

	info = skb_xfrm_md_info(skb);
	if (!info)
		return -EINVAL;

	to->if_id = info->if_id;
	to->link = info->link;
	return 0;
}

/* bpf_skb_get_xfrm_info - Set XFRM metadata
 *
 * Parameters:
 * @skb_ctx	- Pointer to ctx (__sk_buff) in TC program
 *		    Cannot be NULL
 * @from	- Pointer to memory from which the metadata will be copied
 *		    Cannot be NULL
 */
__bpf_kfunc int bpf_skb_set_xfrm_info(struct __sk_buff *skb_ctx, const struct bpf_xfrm_info *from)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct metadata_dst *md_dst;
	struct xfrm_md_info *info;

	if (unlikely(skb_metadata_dst(skb)))
		return -EINVAL;

	if (!xfrm_bpf_md_dst) {
		struct metadata_dst __percpu *tmp;

		tmp = metadata_dst_alloc_percpu(0, METADATA_XFRM, GFP_ATOMIC);
		if (!tmp)
			return -ENOMEM;
		if (cmpxchg(&xfrm_bpf_md_dst, NULL, tmp))
			metadata_dst_free_percpu(tmp);
	}
	md_dst = this_cpu_ptr(xfrm_bpf_md_dst);

	info = &md_dst->u.xfrm_info;

	info->if_id = from->if_id;
	info->link = from->link;
	skb_dst_force(skb);
	info->dst_orig = skb_dst(skb);

	dst_hold((struct dst_entry *)md_dst);
	skb_dst_set(skb, (struct dst_entry *)md_dst);
	return 0;
}

__bpf_kfunc_end_defs();

BTF_SET8_START(xfrm_ifc_kfunc_set)
BTF_ID_FLAGS(func, bpf_skb_get_xfrm_info)
BTF_ID_FLAGS(func, bpf_skb_set_xfrm_info)
BTF_SET8_END(xfrm_ifc_kfunc_set)

static const struct btf_kfunc_id_set xfrm_interface_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &xfrm_ifc_kfunc_set,
};

int __init register_xfrm_interface_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &xfrm_interface_kfunc_set);
}

#endif /* xfrm interface */

/* bpf_xfrm_state_opts - Options for XFRM state lookup helpers
 *
 * Members:
 * @error      - Out parameter, set for any errors encountered
 *		 Values:
 *		   -EINVAL - netns_id is less than -1
 *		   -EINVAL - opts__sz isn't BPF_XFRM_STATE_OPTS_SZ
 *		   -ENONET - No network namespace found for netns_id
 * @netns_id	- Specify the network namespace for lookup
 *		 Values:
 *		   BPF_F_CURRENT_NETNS (-1)
 *		     Use namespace associated with ctx
 *		   [0, S32_MAX]
 *		     Network Namespace ID
 * @mark	- XFRM mark to match on
 * @daddr	- Destination address to match on
 * @spi		- Security parameter index to match on
 * @proto	- L3 protocol to match on
 * @family	- L3 protocol family to match on
 */
struct bpf_xfrm_state_opts {
	s32 error;
	s32 netns_id;
	u32 mark;
	xfrm_address_t daddr;
	__be32 spi;
	u8 proto;
	u16 family;
};

enum {
	BPF_XFRM_STATE_OPTS_SZ = sizeof(struct bpf_xfrm_state_opts),
};

__bpf_kfunc_start_defs();

/* bpf_xdp_get_xfrm_state - Get XFRM state
 *
 * Parameters:
 * @ctx	- Pointer to ctx (xdp_md) in XDP program
 *		    Cannot be NULL
 * @opts	- Options for lookup (documented above)
 *		    Cannot be NULL
 * @opts__sz	- Length of the bpf_xfrm_state_opts structure
 *		    Must be BPF_XFRM_STATE_OPTS_SZ
 */
__bpf_kfunc struct xfrm_state *
bpf_xdp_get_xfrm_state(struct xdp_md *ctx, struct bpf_xfrm_state_opts *opts, u32 opts__sz)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct net *net = dev_net(xdp->rxq->dev);
	struct xfrm_state *x;

	if (!opts || opts__sz < sizeof(opts->error))
		return NULL;

	if (opts__sz != BPF_XFRM_STATE_OPTS_SZ) {
		opts->error = -EINVAL;
		return NULL;
	}

	if (unlikely(opts->netns_id < BPF_F_CURRENT_NETNS)) {
		opts->error = -EINVAL;
		return NULL;
	}

	if (opts->netns_id >= 0) {
		net = get_net_ns_by_id(net, opts->netns_id);
		if (unlikely(!net)) {
			opts->error = -ENONET;
			return NULL;
		}
	}

	x = xfrm_state_lookup(net, opts->mark, &opts->daddr, opts->spi,
			      opts->proto, opts->family);

	if (opts->netns_id >= 0)
		put_net(net);

	return x;
}

__bpf_kfunc_end_defs();

BTF_SET8_START(xfrm_state_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_get_xfrm_state, KF_RET_NULL | KF_ACQUIRE)
BTF_SET8_END(xfrm_state_kfunc_set)

static const struct btf_kfunc_id_set xfrm_state_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &xfrm_state_kfunc_set,
};

int __init register_xfrm_state_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					 &xfrm_state_xdp_kfunc_set);
}
