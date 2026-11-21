// SPDX-License-Identifier: GPL-2.0
/*
 * Handler for Realtek 8 byte switch tags
 *
 * Copyright (C) 2021 Alvin Šipraga <alsi@bang-olufsen.dk>
 *
 * NOTE: Currently only supports protocol "4" found in the RTL8365MB, hence
 * named tag_rtl8_4.
 *
 * This tag has the following format:
 *
 *  0                                  7|8                                 15
 *  |-----------------------------------+-----------------------------------|---
 *  |                               (16-bit)                                | ^
 *  |                       Realtek EtherType [0x8899]                      | |
 *  |-----------------------------------+-----------------------------------| 8
 *  |              (8-bit)              |              (8-bit)              |
 *  |          Protocol [0x04]          |              REASON               | b
 *  |-----------------------------------+-----------------------------------| y
 *  |   (1)   |   (3)  |   (1)  |  (3)  | (1)  | (1)  |    (1)     |  (5)   | t
 *  | EFID_EN |  EFID  | PRI_EN |  PRI  | KEEP | VSEL | LEARN_DIS  |  VIDX  | e
 *  |-----------------------------------+-----------------------------------| s
 *  |   (1)  |                       (15-bit)                               | |
 *  |  ALLOW |                        TX/RX                                 | v
 *  |-----------------------------------+-----------------------------------|---
 *
 * With the following field descriptions:
 *
 *    field      | description
 *   ------------+-------------
 *    Realtek    | 0x8899: indicates that this is a proprietary Realtek tag;
 *     EtherType |         note that Realtek uses the same EtherType for
 *               |         other incompatible tag formats (e.g. tag_rtl4_a.c)
 *    Protocol   | 0x04: indicates that this tag conforms to this format
 *   ------------+-------------
 *    REASON     | reason for forwarding packet to CPU
 *               | 0: packet was forwarded or flooded to CPU
 *               | 80: packet was trapped to CPU
 *    EFID_EN    | 1: packet has an EFID
 *               | 0: no EFID
 *    EFID       | Extended filter ID (EFID) of packet (if EFID_EN=1)
 *    PRI_EN     | 1: force priority of packet
 *               | 0: don't force priority
 *    PRI        | priority of packet (if PRI_EN=1)
 *    KEEP       | preserve packet VLAN tag format
 *    VSEL       | 0: switch should classify packet according to VLAN tag
 *               | 1: switch should classify packet according to VLAN membership
 *               |    configuration with index VIDX
 *    LEARN_DIS  | don't learn the source MAC address of the packet
 *    VIDX       | index of a VLAN membership configuration to use with VSEL
 *    ALLOW      | 1: treat TX/RX field as an allowance port mask, meaning the
 *               |    packet may only be forwarded to ports specified in the
 *               |    mask
 *               | 0: no allowance port mask, TX/RX field is the forwarding
 *               |    port mask
 *    TX/RX      | TX (switch->CPU): port number the packet was received on
 *               | RX (CPU->switch): forwarding port mask (if ALLOW=0)
 *               |                   allowance port mask (if ALLOW=1)
 *
 * The tag can be positioned before Ethertype, using tag "rtl8_4":
 *
 *  +--------+--------+------------+------+-----
 *  | MAC DA | MAC SA | 8 byte tag | Type | ...
 *  +--------+--------+------------+------+-----
 *
 * The tag can also appear between the end of the payload and before the CRC,
 * using tag "rtl8_4t":
 *
 * +--------+--------+------+-----+---------+------------+-----+
 * | MAC DA | MAC SA | TYPE | ... | payload | 8-byte tag | CRC |
 * +--------+--------+------+-----+---------+------------+-----+
 *
 * The added bytes after the payload will break most checksums, either in
 * software or hardware. To avoid this issue, if the checksum is still pending,
 * this tagger checksums the packet in software before adding the tag.
 *
 * This 8 byte switch tag can also be found on RTL9607C family of SoCs with
 * identical protocol "4", but the format is slightly different.
 *
 * On switch->CPU the bytes 4-7 look like this:
 *
 *  |-----------------------------------+-----------------------------------|
 *  | (3) |     (3)    |    (5)         |     (2)     |  (1)  |  (1) |  (4) |
 *  | PRI |   EXTSPA  OR PON_STREAM_ID  |PON_STREAM_ID|L3ROUTE| ORIG | PORT |
 *  |-----------------------------------+-----------------------------------|
 *  |    (1)   |           (15-bit)     /      (6-bit)                      |
 *  |    FBI   |      FLOW_BASED_HASH   /   DST_PORT_MASK                   |
 *  |-----------------------------------+-----------------------------------|
 *
 * On CPU->Switch however the byte 3 is also different:
 *
 *  |-----------------------------------+-----------------------------------|
 *  |              (8-bit)              |             (8-bit)               |
 *  |          Protocol [0x04]          |         TX_PORTMASK_LOW           |
 *  |-----------------------------------+-----------------------------------|
 *  |     (3-bit)    |(1)|   (1)  | (3) |(1) |(1)|   (1)   |(1) |(2)| (1) |1|
 *  |TX_PORTMASK_HIGH| X | PRI_EN | PRI |KEEP| X |LEARN_DIS|PSEL| X |DIRTX|X|
 *  |-----------------------------------+-----------------------------------|
 *  | (3-bit)|    (2-bit)   |     (4-bit)    |           (7-bit)            |
 *  | EXTSPA |   PPPOE_ACT  |    PPPOE_IDX   |        PON_STREAM_ID         |
 *  |-----------------------------------+-----------------------------------|
 *
 * With the following descriptions for new fields:
 *
 *    field           | description
 *   -----------------+-------------
 *    EXTSPA          | Source Extension Port. Relevant when port is CPU (9, 10, 7).
 *    PON_STREAM_ID   | PON Stream ID (GPON) or LLID index (EPON). Relevant when
 *                    | port is PON (5)
 *    L3ROUTE         | "This frame is an intended routed frames" as per docs
 *    ORIG            | The received frame by NIC is the original packet's format
 *                    | before switch lookup and switch didn't do any modifications
 *    FBI             | Flow Based I...? Only relevant when REASON is FB (aka < 64)
 *    FLOW_BASED_HASH | Flow Based Hash Index.
 *    DST_PORT_MASK   | Switch lookup destination port mask. bit 0: CPU, bit 1-5 are
 *                    | extension ports 0~4.
 *    PSEL            | PON stream id (GPON) / LLID index(EPON) selection.
 *    DIRTX           | Direct TX, whatever that means? Used to be called L34KEEP.
 *    PPPOE_ACT       | Egress action for PPPoE header whose Ether Type = 0x8864.
 *                    | 0: intact, 1: Add PPPoE header, 2: Remove PPPoE header,
 *                    | 3: remarking PPPoE switch TX mac action.
 *    PPPOE_IDX       | PPPoE index pointed to an entry of the PPPoE table in the
 *                    | switch. Switch TX-MAC look PPPoE table up by this index to
 *                    | get PPPoE session ID.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/etherdevice.h>

#include "tag.h"

/* Protocols supported:
 *
 * 0x04 = RTL8365MB / RTL9607C (aka ApolloPro) DSA protocol
 */

#define RTL8_4_NAME			"rtl8_4"
#define RTL8_4T_NAME			"rtl8_4t"
#define RTL8_4AP_NAME			"rtl8_4ap"

#define RTL8_4_TAG_LEN			8

#define RTL8_4_PROTOCOL			GENMASK(15, 8)
#define   RTL8_4_PROTOCOL_RTL8365MB	0x04
#define RTL8_4_REASON			GENMASK(7, 0)
#define   RTL8_4_REASON_FORWARD		0
#define   RTL8_4_REASON_TRAP		80
#define   RTL8_4AP_REASON_BCAST_TRAP	203
#define   RTL8_4AP_REASON_RESV_TRAP	215
#define   RTL8_4AP_REASON_IGMP		219
#define   RTL8_4AP_REASON_RMA		220
#define   RTL8_4AP_REASON_ACL		227

#define RTL8_4AP_RX_LO			GENMASK(7, 0)
#define RTL8_4AP_RX_HI			GENMASK(15, 13)
#define RTL9607C_RX_HI_MSK		GENMASK(10, 8)

#define RTL8_4AP_DIRTX			BIT(1)
#define RTL8_4_LEARN_DIS		BIT(5)
#define RTL8_4_KEEP			BIT(7)

#define RTL8_4_TX			GENMASK(3, 0)
#define RTL8_4_RX			GENMASK(10, 0)

static void rtl8_4ap_write_tag(struct sk_buff *skb, struct net_device *dev,
			       void *tag)
{
	u16 pmask = dsa_xmit_port_mask(skb, dev);
	__be16 tag16[RTL8_4_TAG_LEN / 2];
	u16 pmask_low, pmask_high;

	/* Set Realtek EtherType */
	tag16[0] = htons(ETH_P_REALTEK);

	pmask_low = FIELD_GET(RTL8_4AP_RX_LO, pmask);
	/* Set Protocol; set RX (CPU->switch) low forwarding port mask */
	tag16[1] = htons(FIELD_PREP(RTL8_4_PROTOCOL, RTL8_4_PROTOCOL_RTL8365MB) |
			 FIELD_PREP(RTL8_4AP_RX_LO, pmask_low));

	pmask_high = FIELD_GET(RTL9607C_RX_HI_MSK, pmask);
	/* set high forwarding port mask, KEEP, LEARN_DIS and DIRTX */
	tag16[2] = htons(FIELD_PREP(RTL8_4AP_RX_HI, pmask_high) |
			 FIELD_PREP(RTL8_4_LEARN_DIS, 1) |
			 FIELD_PREP(RTL8_4_KEEP, 1) |
			 FIELD_PREP(RTL8_4AP_DIRTX, 1));

	/* Zero EXTSPA, PPPOE_ACT/IDX and PON_STREAM_ID */
	tag16[3] = 0;

	memcpy(tag, tag16, RTL8_4_TAG_LEN);
}

static struct sk_buff *rtl8_4ap_tag_xmit(struct sk_buff *skb,
					 struct net_device *dev)
{
	skb_push(skb, RTL8_4_TAG_LEN);

	dsa_alloc_etype_header(skb, RTL8_4_TAG_LEN);

	rtl8_4ap_write_tag(skb, dev, dsa_etype_header_pos_tx(skb));

	return skb;
}

static void rtl8_4_write_tag(struct sk_buff *skb, struct net_device *dev,
			     void *tag)
{
	__be16 tag16[RTL8_4_TAG_LEN / 2];

	/* Set Realtek EtherType */
	tag16[0] = htons(ETH_P_REALTEK);

	/* Set Protocol; zero REASON */
	tag16[1] = htons(FIELD_PREP(RTL8_4_PROTOCOL, RTL8_4_PROTOCOL_RTL8365MB));

	/* Zero EFID_EN, EFID, PRI_EN, PRI, VSEL, VIDX; set KEEP, LEARN_DIS */
	tag16[2] = htons(FIELD_PREP(RTL8_4_LEARN_DIS, 1) |
			 FIELD_PREP(RTL8_4_KEEP, 1));

	/* Zero ALLOW; set RX (CPU->switch) forwarding port mask */
	tag16[3] = htons(FIELD_PREP(RTL8_4_RX, dsa_xmit_port_mask(skb, dev)));

	memcpy(tag, tag16, RTL8_4_TAG_LEN);
}

static struct sk_buff *rtl8_4_tag_xmit(struct sk_buff *skb,
				       struct net_device *dev)
{
	skb_push(skb, RTL8_4_TAG_LEN);

	dsa_alloc_etype_header(skb, RTL8_4_TAG_LEN);

	rtl8_4_write_tag(skb, dev, dsa_etype_header_pos_tx(skb));

	return skb;
}

static struct sk_buff *rtl8_4t_tag_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	/* Calculate the checksum here if not done yet as trailing tags will
	 * break either software or hardware based checksum
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb)) {
		kfree_skb(skb);
		return NULL;
	}

	rtl8_4_write_tag(skb, dev, skb_put(skb, RTL8_4_TAG_LEN));

	return skb;
}

static int rtl8_4ap_read_tag(struct sk_buff *skb, struct net_device *dev,
			     void *tag)
{
	__be16 tag16[RTL8_4_TAG_LEN / 2];
	u16 etype;
	u8 reason;
	u8 proto;
	u8 port;

	memcpy(tag16, tag, RTL8_4_TAG_LEN);

	/* Parse Realtek EtherType */
	etype = ntohs(tag16[0]);
	if (unlikely(etype != ETH_P_REALTEK)) {
		dev_warn_ratelimited(&dev->dev,
				     "non-realtek ethertype 0x%04x\n", etype);
		return -EPROTO;
	}

	/* Parse Protocol */
	proto = FIELD_GET(RTL8_4_PROTOCOL, ntohs(tag16[1]));
	if (unlikely(proto != RTL8_4_PROTOCOL_RTL8365MB)) {
		dev_warn_ratelimited(&dev->dev,
				     "unknown realtek protocol 0x%02x\n",
				     proto);
		return -EPROTO;
	}

	/* Parse REASON */
	reason = FIELD_GET(RTL8_4_REASON, ntohs(tag16[1]));

	/* Parse TX (switch->CPU) */
	port = FIELD_GET(RTL8_4_TX, ntohs(tag16[2]));
	skb->dev = dsa_conduit_find_user(dev, 0, port);
	if (!skb->dev) {
		dev_warn_ratelimited(&dev->dev,
				     "could not find user for port %d\n",
				     port);
		return -ENOENT;
	}

	switch (reason) {
	case RTL8_4AP_REASON_BCAST_TRAP:
	case RTL8_4AP_REASON_RESV_TRAP:
	case RTL8_4AP_REASON_IGMP:
	case RTL8_4AP_REASON_RMA:
	case RTL8_4AP_REASON_ACL:
		break;
	default:
		dsa_default_offload_fwd_mark(skb);
		break;
	}

	return 0;
}

static struct sk_buff *rtl8_4ap_tag_rcv(struct sk_buff *skb,
					struct net_device *dev)
{
	if (unlikely(!pskb_may_pull(skb, RTL8_4_TAG_LEN))) {
		kfree_skb(skb);
		return NULL;
	}

	if (unlikely(rtl8_4ap_read_tag(skb, dev,
				       dsa_etype_header_pos_rx(skb)))) {
		kfree_skb(skb);
		return NULL;
	}

	/* Remove tag and recalculate checksum */
	skb_pull_rcsum(skb, RTL8_4_TAG_LEN);

	dsa_strip_etype_header(skb, RTL8_4_TAG_LEN);

	return skb;
}

static int rtl8_4_read_tag(struct sk_buff *skb, struct net_device *dev,
			   void *tag)
{
	__be16 tag16[RTL8_4_TAG_LEN / 2];
	u16 etype;
	u8 reason;
	u8 proto;
	u8 port;

	memcpy(tag16, tag, RTL8_4_TAG_LEN);

	/* Parse Realtek EtherType */
	etype = ntohs(tag16[0]);
	if (unlikely(etype != ETH_P_REALTEK)) {
		dev_warn_ratelimited(&dev->dev,
				     "non-realtek ethertype 0x%04x\n", etype);
		return -EPROTO;
	}

	/* Parse Protocol */
	proto = FIELD_GET(RTL8_4_PROTOCOL, ntohs(tag16[1]));
	if (unlikely(proto != RTL8_4_PROTOCOL_RTL8365MB)) {
		dev_warn_ratelimited(&dev->dev,
				     "unknown realtek protocol 0x%02x\n",
				     proto);
		return -EPROTO;
	}

	/* Parse REASON */
	reason = FIELD_GET(RTL8_4_REASON, ntohs(tag16[1]));

	/* Parse TX (switch->CPU) */
	port = FIELD_GET(RTL8_4_TX, ntohs(tag16[3]));
	skb->dev = dsa_conduit_find_user(dev, 0, port);
	if (!skb->dev) {
		dev_warn_ratelimited(&dev->dev,
				     "could not find user for port %d\n",
				     port);
		return -ENOENT;
	}

	if (reason != RTL8_4_REASON_TRAP)
		dsa_default_offload_fwd_mark(skb);

	return 0;
}

static struct sk_buff *rtl8_4_tag_rcv(struct sk_buff *skb,
				      struct net_device *dev)
{
	if (unlikely(!pskb_may_pull(skb, RTL8_4_TAG_LEN))) {
		kfree_skb(skb);
		return NULL;
	}

	if (unlikely(rtl8_4_read_tag(skb, dev, dsa_etype_header_pos_rx(skb)))) {
		kfree_skb(skb);
		return NULL;
	}

	/* Remove tag and recalculate checksum */
	skb_pull_rcsum(skb, RTL8_4_TAG_LEN);

	dsa_strip_etype_header(skb, RTL8_4_TAG_LEN);

	return skb;
}

static struct sk_buff *rtl8_4t_tag_rcv(struct sk_buff *skb,
				       struct net_device *dev)
{
	if (skb_linearize(skb)) {
		kfree_skb(skb);
		return NULL;
	}

	if (unlikely(rtl8_4_read_tag(skb, dev, skb_tail_pointer(skb) - RTL8_4_TAG_LEN))) {
		kfree_skb(skb);
		return NULL;
	}

	if (pskb_trim_rcsum(skb, skb->len - RTL8_4_TAG_LEN)) {
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

/* Ethertype version */
static const struct dsa_device_ops rtl8_4_netdev_ops = {
	.name = "rtl8_4",
	.proto = DSA_TAG_PROTO_RTL8_4,
	.xmit = rtl8_4_tag_xmit,
	.rcv = rtl8_4_tag_rcv,
	.needed_headroom = RTL8_4_TAG_LEN,
};

DSA_TAG_DRIVER(rtl8_4_netdev_ops);

MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_RTL8_4, RTL8_4_NAME);

/* Tail version */
static const struct dsa_device_ops rtl8_4t_netdev_ops = {
	.name = "rtl8_4t",
	.proto = DSA_TAG_PROTO_RTL8_4T,
	.xmit = rtl8_4t_tag_xmit,
	.rcv = rtl8_4t_tag_rcv,
	.needed_tailroom = RTL8_4_TAG_LEN,
};

DSA_TAG_DRIVER(rtl8_4t_netdev_ops);

MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_RTL8_4T, RTL8_4T_NAME);

/* Ethertype RTL9607C version */
static const struct dsa_device_ops rtl8_4ap_netdev_ops = {
	.name = "rtl8_4ap",
	.proto = DSA_TAG_PROTO_RTL8_4AP,
	.xmit = rtl8_4ap_tag_xmit,
	.rcv = rtl8_4ap_tag_rcv,
	.needed_headroom = RTL8_4_TAG_LEN,
};

DSA_TAG_DRIVER(rtl8_4ap_netdev_ops);

MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_RTL8_4AP, RTL8_4AP_NAME);

static struct dsa_tag_driver *dsa_tag_drivers[] = {
	&DSA_TAG_DRIVER_NAME(rtl8_4_netdev_ops),
	&DSA_TAG_DRIVER_NAME(rtl8_4t_netdev_ops),
	&DSA_TAG_DRIVER_NAME(rtl8_4ap_netdev_ops),
};
module_dsa_tag_drivers(dsa_tag_drivers);

MODULE_DESCRIPTION("DSA tag driver for Realtek 8 byte protocol 4 tags");
MODULE_LICENSE("GPL");
