// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#include <linux/bitops.h>
#include <linux/byteorder/generic.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/unaligned.h>

#include "tag.h"

#define SDSA_HLEN	8

#define SDSA_NAME	"sdsa"
#define ETH_P_SDSA	0xDCDC

/* SDSA tag byte layout (after the 12-byte MAC header):
 * Bytes 0-1: SDSA EtherType (0xDCDC)
 * Bytes 2-3: Reserved
 * Byte 4:    Frame type (bits 7-6), VLAN-info bit (bit 5), port[9:5] (bits 4-0)
 * Byte 5:    Port[4:0] (bits 7-3)
 * Bytes 6-7: PCP (bits 7-5) / CFI (bit 4) / VID (bits 3-0 + byte 7), only
 *            meaningful when the VLAN-info bit is set.
 */
#define SDSA_TAG_FRAME_TYPE_MASK	GENMASK(7, 6)
#define SDSA_TAG_VLAN_BIT		BIT(5)
#define SDSA_TAG_PORT_HI_MASK		GENMASK(4, 0)
#define SDSA_TAG_PORT_LO_MASK		GENMASK(7, 3)
#define SDSA_TAG_PORT_HI_SHIFT		5
#define SDSA_FRAME_TYPE_TO_CPU		0
#define SDSA_FRAME_TYPE_FROM_CPU	1

struct sdsa_tag {
	__be16 ethertype;
	__be16 reserved;
	u8 frame_type_port_hi;
	u8 port_lo;
	__be16 vlan;
};

static struct sk_buff *sdsa_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct dsa_port *dp = dsa_user_to_port(dev);
	struct sdsa_tag *tag;
	u16 vlan_tci;

	BUILD_BUG_ON(sizeof(*tag) != SDSA_HLEN);

	skb_push(skb, SDSA_HLEN);
	dsa_alloc_etype_header(skb, SDSA_HLEN);

	tag = dsa_etype_header_pos_tx(skb);
	tag->ethertype = cpu_to_be16(ETH_P_SDSA);
	tag->reserved = 0;
	tag->frame_type_port_hi =
		FIELD_PREP(SDSA_TAG_FRAME_TYPE_MASK, SDSA_FRAME_TYPE_FROM_CPU) |
		FIELD_PREP(SDSA_TAG_PORT_HI_MASK,
			   dp->index >> SDSA_TAG_PORT_HI_SHIFT);
	tag->port_lo = FIELD_PREP(SDSA_TAG_PORT_LO_MASK, dp->index);
	/* SDSA carries no TPID, so only encode 802.1Q C-tags. */
	if (skb_vlan_tag_present(skb) &&
	    skb->vlan_proto == htons(ETH_P_8021Q)) {
		vlan_tci = skb_vlan_tag_get(skb);
		__vlan_hwaccel_clear_tag(skb);
		tag->frame_type_port_hi |= SDSA_TAG_VLAN_BIT;
		tag->vlan = cpu_to_be16(vlan_tci);
	} else {
		tag->vlan = 0;
	}

	return skb;
}

static struct sk_buff *sdsa_rcv(struct sk_buff *skb, struct net_device *dev)
{
	enum skb_drop_reason reason;
	struct sdsa_tag *tag;
	u16 dummy_vlan_tci;
	bool vlan_present;
	int source_port;
	u16 encap_proto;
	u8 frame_type;
	u16 vlan_tci;

	if (unlikely(!pskb_may_pull(skb, SDSA_HLEN))) {
		reason = SKB_DROP_REASON_HDR_TRUNC;
		goto out_drop;
	}

	tag = dsa_etype_header_pos_rx(skb);
	if (unlikely(be16_to_cpu(tag->ethertype) != ETH_P_SDSA)) {
		reason = SKB_DROP_REASON_DEV_HDR;
		goto out_drop;
	}

	frame_type = FIELD_GET(SDSA_TAG_FRAME_TYPE_MASK,
			       tag->frame_type_port_hi);
	if (frame_type != SDSA_FRAME_TYPE_TO_CPU) {
		reason = SKB_DROP_REASON_DEV_HDR;
		goto out_drop;
	}

	vlan_present = tag->frame_type_port_hi & SDSA_TAG_VLAN_BIT;
	vlan_tci = be16_to_cpu(tag->vlan);
	encap_proto = get_unaligned_be16((u8 *)tag + SDSA_HLEN);

	source_port = FIELD_GET(SDSA_TAG_PORT_HI_MASK,
				tag->frame_type_port_hi) <<
		      SDSA_TAG_PORT_HI_SHIFT;
	source_port |= FIELD_GET(SDSA_TAG_PORT_LO_MASK, tag->port_lo);

	skb->dev = dsa_conduit_find_user(dev, 0, source_port);
	if (!skb->dev) {
		reason = SKB_DROP_REASON_DEV_HDR;
		goto out_drop;
	}

	skb_pull_rcsum(skb, SDSA_HLEN);
	dsa_strip_etype_header(skb, SDSA_HLEN);
	if (vlan_present) {
		if (encap_proto == ETH_P_8021Q) {
			skb_push_rcsum(skb, ETH_HLEN);
			skb_reset_mac_header(skb);
			if (__skb_vlan_pop(skb, &dummy_vlan_tci)) {
				reason = SKB_DROP_REASON_NOMEM;
				goto out_drop;
			}
			skb_pull_rcsum(skb, ETH_HLEN);
		}

		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
	}

	dsa_default_offload_fwd_mark(skb);
	return skb;

out_drop:
	kfree_skb_reason(skb, reason);
	return NULL;
}

static const struct dsa_device_ops sdsa_netdev_ops = {
	.name = SDSA_NAME,
	.proto = DSA_TAG_PROTO_SDSA,
	.xmit = sdsa_xmit,
	.rcv = sdsa_rcv,
	.needed_headroom = SDSA_HLEN,
};

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DSA tag driver for SoC-e SDSA protocol");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_SDSA, SDSA_NAME);

module_dsa_tag_driver(sdsa_netdev_ops);
