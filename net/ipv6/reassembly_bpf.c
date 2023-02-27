// SPDX-License-Identifier: GPL-2.0-only
/* Unstable ipv6 fragmentation helpers for TC-BPF hook
 *
 * These are called from SCHED_CLS BPF programs. Note that it is allowed to
 * break compatibility for these functions since the interface they are exposed
 * through to BPF programs is explicitly unstable.
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/netdevice.h>
#include <net/ipv6.h>
#include <net/ipv6_frag.h>
#include <net/ipv6_stubs.h>

static int set_dst(struct sk_buff *skb, struct net *net)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct dst_entry *dst;

	struct flowi6 fl6 = {
		.flowi6_flags = FLOWI_FLAG_ANYSRC,
		.flowi6_mark  = skb->mark,
		.flowlabel    = ip6_flowinfo(ip6h),
		.flowi6_iif   = skb->skb_iif,
		.flowi6_proto = ip6h->nexthdr,
		.daddr	      = ip6h->daddr,
		.saddr	      = ip6h->saddr,
	};

	dst = ipv6_stub->ipv6_dst_lookup_flow(net, NULL, &fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	skb_dst_set(skb, dst);

	return 0;
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in reassembly BTF");

/* bpf_ipv6_frag_rcv - Defragment an ipv6 packet
 *
 * This helper takes an skb as input. If this skb successfully reassembles
 * the original packet, the skb is updated to contain the original, reassembled
 * packet.
 *
 * Otherwise (on error or incomplete reassembly), the input skb remains
 * unmodified.
 *
 * Parameters:
 * @ctx		- Pointer to program context (skb)
 * @netns	- Child network namespace id. If value is a negative signed
 *		  32-bit integer, the netns of the device in the skb is used.
 *
 * Return:
 * 0 on successfully reassembly or non-fragmented packet. Negative value on
 * error or incomplete reassembly.
 */
int bpf_ipv6_frag_rcv(struct __sk_buff *ctx, u64 netns)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct sk_buff *skb_cpy;
	struct net *caller_net;
	unsigned int foff;
	struct net *net;
	int mac_len;
	void *mac;
	int err;

	if (unlikely(!((s32)netns < 0 || netns <= S32_MAX)))
		return -EINVAL;

	caller_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	if ((s32)netns < 0) {
		net = caller_net;
	} else {
		net = get_net_ns_by_id(caller_net, netns);
		if (unlikely(!net))
			return -EINVAL;
	}

	err = set_dst(skb, net);
	if (err < 0)
		return err;

	mac_len = skb->mac_len;
	skb_cpy = skb_copy(skb, GFP_ATOMIC);
	if (!skb_cpy)
		return -ENOMEM;

	/* _ipv6_frag_rcv() expects skb->transport_header to be set to start of
	 * the frag header and nhoff to be set.
	 */
	err = ipv6_find_hdr(skb_cpy, &foff, NEXTHDR_FRAGMENT, NULL, NULL);
	if (err < 0)
		return err;
	skb_set_transport_header(skb_cpy, foff);
	IP6CB(skb_cpy)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	/* inet6_protocol handlers return >0 on success, 0 on out of band
	 * consumption, <0 on error. We never expect to see 0 here.
	 */
	err = _ipv6_frag_rcv(net, skb_cpy, IP6_DEFRAG_BPF);
	if (err < 0)
		return err;
	else if (err == 0)
		return -EINVAL;

	skb_morph(skb, skb_cpy);
	kfree_skb(skb_cpy);

	/* _ipv6_frag_rcv() does not maintain mac header, so push empty header
	 * in so prog sees the correct layout. The empty mac header will be
	 * later pulled from cls_bpf.
	 */
	skb->mac_len = mac_len;
	mac = skb_push(skb, mac_len);
	memset(mac, 0, mac_len);
	bpf_compute_data_pointers(skb);

	return 0;
}

__diag_pop()

BTF_SET8_START(ipv6_reassembly_kfunc_set)
BTF_ID_FLAGS(func, bpf_ipv6_frag_rcv, KF_CHANGES_PKT)
BTF_SET8_END(ipv6_reassembly_kfunc_set)

static const struct btf_kfunc_id_set ipv6_reassembly_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ipv6_reassembly_kfunc_set,
};

int register_ipv6_reassembly_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &ipv6_reassembly_bpf_kfunc_set);
}
