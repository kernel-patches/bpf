/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __XSK_PACKET_H__
#define __XSK_PACKET_H__
extern struct list_head xsk_pt __read_mostly;

void __xsk_pt_deliver(struct xdp_sock *xs, struct sk_buff *skb,
		      struct xdp_desc *desc, bool rx);

static inline void xsk_tx_packet_deliver(struct xdp_sock *xs,
					 struct xdp_desc *desc,
					 struct sk_buff *skb)
{
	if (likely(list_empty(&xsk_pt)))
		return;

	local_bh_disable();
	__xsk_pt_deliver(xs, skb, desc, false);
	local_bh_enable();
}

static inline void xsk_tx_zc_packet_deliver(struct xdp_sock *xs,
					    struct xdp_desc *desc)
{
	if (likely(list_empty(&xsk_pt)))
		return;

	__xsk_pt_deliver(xs, NULL, desc, false);
}

static inline void xsk_rx_packet_deliver(struct xdp_sock *xs, u64 addr, u32 len)
{
	struct xdp_desc desc;

	if (likely(list_empty(&xsk_pt)))
		return;

	desc.addr = addr;
	desc.len = len;

	__xsk_pt_deliver(xs, NULL, &desc, true);
}

#endif /* __XSK_PACKET_H__ */
