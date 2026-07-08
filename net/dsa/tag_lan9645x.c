// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/dsa/lan9645x.h>

#include "tag.h"

#define LAN9645X_NAME "lan9645x"

#define BTM_MSK(n)	((u8)GENMASK(n, 0))
#define TOP_MSK(n)	((u8)GENMASK(7, n))

static inline void set_merge_mask(u8 *on_zero, u8 on_one, u8 mask)
{
	*on_zero = *on_zero ^ ((*on_zero ^ on_one) & mask);
}

/* The internal frame header (IFH) is a big-endian 28 byte unpadded bit array.
 * Frames can be prepended with an IFH on injection and extraction. There
 * are two field layouts, one for extraction and one for injection.
 *
 *    IFH bits go from high to low, for instance
 *    ifh[0]  = [223:216]
 *    ifh[27] = [7:0]
 *
 * Here is an example of setting a value starting at bit 13 of bit length 17.
 *
 * val    = 0x1ff
 * pos    = 13
 * length = 17
 *
 *
 * IFH[]   0                         23       24       25        26      27
 *
 *                                           end_u8           start_u8
 *      +--------+----------------+--------+--------+--------+--------+--------+
 *      |        |                |        |        |        |        |        |
 * IFH  |        | ....           |        |  vvvvvvvvvvvvvvvvvvv     |        |
 *      |        |                |        |  |     |        |  |     |        |
 *      +--------+----------------+--------+--+-----+--------+--+-----+--------+
 * Bits  223                       39    32 31|   24 23    16 15|    8 7      0
 *                                            |                 |
 *                                            |                 |
 *                                            |                 |
 *                                            v                 v
 *                                        end       = 29       pos        = 13
 *                                        end_rem   = 5        pos_rem    = 5
 *                                        end_u8    = 3        start_u8   = 1
 *                                        BTM_MSK(5)= 0x3f     TOP_MSK(5) = 0xe0
 *
 *
 * In end_u8 and start_u8 we must merge the existing IFH byte with the new
 * value. In the 'middle' bytes of the value we can overwrite the corresponding
 * IFH byte.
 */
static __always_inline void lan9645x_ifh_set(u8 *ifh, u32 val, size_t pos,
					     size_t length)
{
	size_t end = (pos + length) - 1;
	size_t end_rem = end & 0x7;
	size_t pos_rem = pos & 0x7;
	size_t start_u8 = pos >> 3;
	size_t end_u8 = end >> 3;
	u8 end_mask, start_mask;
	size_t vshift;
	u8 *ptr;

	BUILD_BUG_ON_MSG(length > 32, "IFH field size wider than 32.");
	BUILD_BUG_ON_MSG(length == 0, "IFH field size of 0.");
	BUILD_BUG_ON_MSG(pos + length > LAN9645X_IFH_BITS,
			 "IFH field overflows IFH");

	end_mask = BTM_MSK(end_rem);
	start_mask = TOP_MSK(pos_rem);

	ptr = &ifh[LAN9645X_IFH_LEN - 1 - end_u8];

	if (end_u8 == start_u8)
		return set_merge_mask(ptr, val << pos_rem,
				      end_mask & start_mask);

	vshift = length - end_rem - 1;
	set_merge_mask(ptr++, val >> vshift, end_mask);

	for (size_t j = 1; j < end_u8 - start_u8; j++) {
		vshift -= 8;
		*ptr++ = val >> vshift;
	}

	set_merge_mask(ptr, val << pos_rem, start_mask);
}

static __always_inline u32 lan9645x_ifh_get(const u8 *ifh, size_t pos,
					    size_t length)
{
	size_t end = (pos + length) - 1;
	size_t end_rem = end & 0x7;
	size_t pos_rem = pos & 0x7;
	size_t start_u8 = pos >> 3;
	size_t end_u8 = end >> 3;
	u8 end_mask, start_mask;
	const u8 *ptr;
	u32 val;

	BUILD_BUG_ON_MSG(length > 32, "IFH field size wider than 32.");
	BUILD_BUG_ON_MSG(length == 0, "IFH field size of 0.");
	BUILD_BUG_ON_MSG(pos + length > LAN9645X_IFH_BITS,
			 "IFH field overflows IFH");

	end_mask = BTM_MSK(end_rem);
	start_mask = TOP_MSK(pos_rem);

	ptr = &ifh[LAN9645X_IFH_LEN - 1 - end_u8];

	if (end_u8 == start_u8)
		return (*ptr & end_mask & start_mask) >> pos_rem;

	val = *ptr++ & end_mask;

	for (size_t j = 1; j < end_u8 - start_u8; j++)
		val = val << 8 | *ptr++;

	return val << (8 - pos_rem) | (*ptr & start_mask) >> pos_rem;
}

static void lan9645x_xmit_get_vlan_info(struct sk_buff *skb,
					struct net_device *br,
					u32 *vlan_tci, u32 *tag_type)
{
	struct vlan_ethhdr *hdr;
	u16 proto, tci;

	if (!br || !br_vlan_enabled(br)) {
		*vlan_tci = 0;
		*tag_type = LAN9645X_IFH_TAG_TYPE_C;
		return;
	}

	hdr = (struct vlan_ethhdr *)skb_mac_header(skb);
	br_vlan_get_proto(br, &proto);

	if (skb_headlen(skb) >= VLAN_ETH_HLEN &&
	    ntohs(hdr->h_vlan_proto) == proto) {
		vlan_remove_tag(skb, &tci);
		*vlan_tci = tci;
	} else {
		rcu_read_lock();
		br_vlan_get_pvid_rcu(br, &tci);
		rcu_read_unlock();
		*vlan_tci = tci;
	}

	*tag_type = (proto != ETH_P_8021Q) ? LAN9645X_IFH_TAG_TYPE_S :
					     LAN9645X_IFH_TAG_TYPE_C;
}

static void lan9645x_offload_fwd_mark(struct sk_buff *skb, u32 cpuq)
{
	/* Trapped frames must be forwarded by the stack. */
	if (cpuq & BIT(LAN9645X_CPUQ_TRAP)) {
		skb->offload_fwd_mark = 0;
		return;
	}

	dsa_default_offload_fwd_mark(skb);
}

static struct sk_buff *lan9645x_xmit(struct sk_buff *skb,
				     struct net_device *ndev)
{
	struct dsa_port *dp = dsa_user_to_port(ndev);
	struct dsa_switch *ds = dp->ds;
	u32 vlan_tci, tag_type;
	u32 qos_class;
	void *ifh;

	lan9645x_xmit_get_vlan_info(skb, dsa_port_bridge_dev_get(dp), &vlan_tci,
				    &tag_type);

	/* We need to make sure frame has the proper size after IFH is stripped
	 * by hw.
	 */
	if (__skb_put_padto(skb, ETH_ZLEN, false))
		return NULL;

	qos_class = netdev_get_num_tc(ndev) ?
		    netdev_get_prio_tc_map(ndev, skb->priority) :
		    skb->priority;

	/* Make room for IFH */
	ifh = skb_push(skb, LAN9645X_IFH_LEN);
	memset(ifh, 0, LAN9645X_IFH_LEN);

	lan9645x_ifh_set(ifh, 1, IFH_BYPASS, IFH_BYPASS_SZ);
	lan9645x_ifh_set(ifh, ds->num_ports, IFH_SRCPORT, IFH_SRCPORT_SZ);
	lan9645x_ifh_set(ifh, tag_type, IFH_TAG_TYPE, IFH_TAG_TYPE_SZ);
	lan9645x_ifh_set(ifh, vlan_tci, IFH_TCI, IFH_TCI_SZ);
	lan9645x_ifh_set(ifh, qos_class, IFH_QOS_CLASS, IFH_QOS_CLASS_SZ);
	lan9645x_ifh_set(ifh, BIT(dp->index), IFH_DSTS, IFH_DSTS_SZ);

	return skb;
}

static struct sk_buff *lan9645x_rcv(struct sk_buff *skb,
				    struct net_device *ndev)
{
	u32 src_port, qos_class, vlan_tci, tag_type, popcnt, etype_ofs, cpuq;
	struct dsa_port *dp;
	u32 ifh_gap_len = 0;
	u16 vlan_tpid;
	u8 *ifh;

	/* DSA master already consumed DMAC,SMAC,ETYPE from long prefix. Go back
	 * to beginning of frame.
	 */
	skb_push(skb, ETH_HLEN);

	if (unlikely(!pskb_may_pull(skb, LAN9645X_TOTAL_TAG_LEN)))
		return NULL;

	/* IFH starts after our long prefix */
	ifh = skb_pull(skb, LAN9645X_LONG_PREFIX_LEN);

	popcnt = lan9645x_ifh_get(ifh, IFH_POP_CNT, IFH_POP_CNT_SZ);
	etype_ofs = lan9645x_ifh_get(ifh, IFH_ETYPE_OFS, IFH_ETYPE_OFS_SZ);
	src_port = lan9645x_ifh_get(ifh, IFH_SRCPORT, IFH_SRCPORT_SZ);
	tag_type = lan9645x_ifh_get(ifh, IFH_TAG_TYPE, IFH_TAG_TYPE_SZ);
	vlan_tci = lan9645x_ifh_get(ifh, IFH_TCI, IFH_TCI_SZ);
	qos_class = lan9645x_ifh_get(ifh, IFH_QOS_CLASS, IFH_QOS_CLASS_SZ);
	cpuq = lan9645x_ifh_get(ifh, IFH_CPUQ, IFH_CPUQ_SZ);

	/* Set skb->data at start of real header
	 *
	 * Since REW_PORT_NO_REWRITE=0 is required on the NPI port, we need to
	 * account for any tags popped by the hardware, as that will leave a gap
	 * between the IFH and DMAC.
	 */
	if (popcnt == 0 && etype_ofs == 0)
		ifh_gap_len = 2 * VLAN_HLEN;
	else if (popcnt == 3)
		ifh_gap_len = VLAN_HLEN;

	skb_pull(skb, LAN9645X_IFH_LEN);

	if (unlikely(!pskb_may_pull(skb, ifh_gap_len + ETH_HLEN)))
		return NULL;

	skb_pull(skb, ifh_gap_len);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_reset_mac_len(skb);

	/* Reset skb->data past the actual ethernet header. */
	skb_pull(skb, ETH_HLEN);

	/* We must deliver the skb so skb->csum only covers the data beyond the
	 * real ethernet header. The fake ethernet header in the prefix is
	 * not part of skb->csum already. We must subtract what remains of the
	 * prefix, the ifh and the gap.
	 */
	skb_postpull_rcsum(skb,
			   skb->data - LAN9645X_TOTAL_TAG_LEN - ifh_gap_len,
			   LAN9645X_TOTAL_TAG_LEN + ifh_gap_len);

	skb->dev = dsa_conduit_find_user(ndev, 0, src_port);
	if (WARN_ON_ONCE(!skb->dev)) {
		/* This should never happen since we have disabled reflection
		 * back to the CPU.
		 */
		return NULL;
	}

	lan9645x_offload_fwd_mark(skb, cpuq);

	skb->priority = qos_class;

	/* While we have REW_PORT_NO_REWRITE=0 on the NPI port, we still disable
	 * port VLAN tagging with REW_TAG_CFG. Any classified VID, different
	 * from a VID in the frame, will not be written to the frame, but is
	 * only communicated via the IFH. So for VLAN-aware ports we add the IFH
	 * vlan to the skb.
	 */
	dp = dsa_user_to_port(skb->dev);
	vlan_tpid = tag_type ? ETH_P_8021AD : ETH_P_8021Q;

	if (dsa_port_is_vlan_filtering(dp) && vlan_tci) {
		u16 port_pvid = 0;

		br_vlan_get_pvid_rcu(skb->dev, &port_pvid);

		if ((vlan_tci & VLAN_VID_MASK) != port_pvid)
			__vlan_hwaccel_put_tag(skb, htons(vlan_tpid), vlan_tci);
	}

	return skb;
}

static const struct dsa_device_ops lan9645x_netdev_ops = {
	.name = LAN9645X_NAME,
	.proto = DSA_TAG_PROTO_LAN9645X,
	.xmit = lan9645x_xmit,
	.rcv = lan9645x_rcv,
	.needed_headroom = LAN9645X_TOTAL_TAG_LEN,
};

MODULE_DESCRIPTION("DSA tag driver for LAN9645x family of switches, using NPI port");
MODULE_LICENSE("GPL");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_LAN9645X, LAN9645X_NAME);

module_dsa_tag_driver(lan9645x_netdev_ops);
