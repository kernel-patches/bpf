// SPDX-License-Identifier: GPL-2.0
/* XDP sockets packet api
 *
 * Author: Xuan Zhuo <xuanzhuo.dxf@linux.alibaba.com>
 */

#include <net/xdp_sock.h>
#include <net/xdp_sock_drv.h>
#include "xsk.h"
#include "xsk_packet.h"

struct list_head xsk_pt __read_mostly;
static DEFINE_SPINLOCK(pt_lock);

static struct sk_buff *xsk_pt_alloc_skb(struct xdp_sock *xs,
					struct xdp_desc *desc)
{
	struct sk_buff *skb;
	void *buffer;
	int err;

	skb = alloc_skb(desc->len, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_put(skb, desc->len);

	buffer = xsk_buff_raw_get_data(xs->pool, desc->addr);
	err = skb_store_bits(skb, 0, buffer, desc->len);
	if (unlikely(err)) {
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

static struct sk_buff *xsk_pt_get_skb(struct xdp_sock *xs,
				      struct xdp_desc *desc,
				      struct sk_buff *skb,
				      bool rx)
{
	struct net_device *dev = xs->dev;

	/* We must copy the data, because skb may exist for a long time
	 * on AF_PACKET. If the buffer of the xsk is used by skb, the
	 * release of xsk and the reuse of the buffer will be affected.
	 */
	if (!skb || (dev->priv_flags & IFF_TX_SKB_NO_LINEAR))
		skb = xsk_pt_alloc_skb(xs, desc);
	else
		skb = skb_clone(skb, GFP_ATOMIC);

	if (!skb)
		return NULL;

	skb->protocol = eth_type_trans(skb, dev);
	skb_reset_network_header(skb);
	skb->transport_header = skb->network_header;
	__net_timestamp(skb);

	if (!rx)
		skb->pkt_type = PACKET_OUTGOING;

	return skb;
}

void __xsk_pt_deliver(struct xdp_sock *xs, struct sk_buff *skb,
		      struct xdp_desc *desc, bool rx)
{
	struct packet_type *pt_prev = NULL;
	struct packet_type *ptype;
	struct xsk_packet *xpt;

	rcu_read_lock();
	list_for_each_entry_rcu(xpt, &xsk_pt, list) {
		ptype = xpt->pt;

		if (!rx && ptype->ignore_outgoing)
			continue;

		if (pt_prev) {
			refcount_inc(&skb->users);
			pt_prev->func(skb, skb->dev, pt_prev, skb->dev);
			pt_prev = ptype;
			continue;
		}

		skb = xsk_pt_get_skb(xs, desc, skb, rx);
		if (unlikely(!skb))
			goto out_unlock;

		pt_prev = ptype;
	}

	if (pt_prev)
		pt_prev->func(skb, skb->dev, pt_prev, skb->dev);

out_unlock:
	rcu_read_unlock();
}

void xsk_add_pack(struct xsk_packet *xpt)
{
	if (xpt->pt->type != htons(ETH_P_ALL))
		return;

	spin_lock(&pt_lock);
	list_add_rcu(&xpt->list, &xsk_pt);
	spin_unlock(&pt_lock);
}

void __xsk_remove_pack(struct xsk_packet *xpt)
{
	struct xsk_packet *xpt1;

	spin_lock(&pt_lock);

	list_for_each_entry(xpt1, &xsk_pt, list) {
		if (xpt1 == xpt) {
			list_del_rcu(&xpt1->list);
			goto out;
		}
	}

	pr_warn("xsk_remove_pack: %p not found\n", xpt);
out:
	spin_unlock(&pt_lock);
}
