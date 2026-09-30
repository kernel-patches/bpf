// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2013-2018, 2021, The Linux Foundation. All rights reserved.
 *
 * RMNET Data MAP protocol
 */

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ipv6.h>
#include <linux/bitfield.h>
#include "rmnet_config.h"
#include "rmnet_map.h"
#include "rmnet_private.h"
#include "rmnet_vnd.h"

#define RMNET_MAP_DEAGGR_SPACING  64
#define RMNET_MAP_DEAGGR_HEADROOM (RMNET_MAP_DEAGGR_SPACING / 2)

struct rmnet_map_coal_metadata {
	void *ip_header;
	void *trans_header;
	u16 ip_len;
	u16 trans_len;
	u16 data_offset;
	u16 data_len;
	u8 ip_proto;
	u8 trans_proto;
	u8 pkt_count;
	bool zero_csum;
};

static __sum16 *rmnet_map_get_csum_field(unsigned char protocol,
					 const void *txporthdr)
{
	if (protocol == IPPROTO_TCP)
		return &((struct tcphdr *)txporthdr)->check;

	if (protocol == IPPROTO_UDP)
		return &((struct udphdr *)txporthdr)->check;

	return NULL;
}

static int
rmnet_map_ipv4_dl_csum_trailer(struct sk_buff *skb,
			       struct rmnet_map_dl_csum_trailer *csum_trailer,
			       struct rmnet_priv *priv)
{
	struct iphdr *ip4h = (struct iphdr *)skb->data;
	void *txporthdr = skb->data + ip4h->ihl * 4;
	__sum16 *csum_field, pseudo_csum;
	__sum16 ip_payload_csum;

	/* Computing the checksum over just the IPv4 header--including its
	 * checksum field--should yield 0.  If it doesn't, the IP header
	 * is bad, so return an error and let the IP layer drop it.
	 */
	if (ip_fast_csum(ip4h, ip4h->ihl)) {
		priv->stats.csum_ip4_header_bad++;
		return -EINVAL;
	}

	/* We don't support checksum offload on IPv4 fragments */
	if (ip_is_fragment(ip4h)) {
		priv->stats.csum_fragmented_pkt++;
		return -EOPNOTSUPP;
	}

	/* Checksum offload is only supported for UDP and TCP protocols */
	csum_field = rmnet_map_get_csum_field(ip4h->protocol, txporthdr);
	if (!csum_field) {
		priv->stats.csum_err_invalid_transport++;
		return -EPROTONOSUPPORT;
	}

	/* RFC 768: UDP checksum is optional for IPv4, and is 0 if unused */
	if (!*csum_field && ip4h->protocol == IPPROTO_UDP) {
		priv->stats.csum_skipped++;
		return 0;
	}

	/* The checksum value in the trailer is computed over the entire
	 * IP packet, including the IP header and payload.  To derive the
	 * transport checksum from this, we first subract the contribution
	 * of the IP header from the trailer checksum.  We then add the
	 * checksum computed over the pseudo header.
	 *
	 * We verified above that the IP header contributes zero to the
	 * trailer checksum.  Therefore the checksum in the trailer is
	 * just the checksum computed over the IP payload.

	 * If the IP payload arrives intact, adding the pseudo header
	 * checksum to the IP payload checksum will yield 0xffff (negative
	 * zero).  This means the trailer checksum and the pseudo checksum
	 * are additive inverses of each other.  Put another way, the
	 * message passes the checksum test if the trailer checksum value
	 * is the negated pseudo header checksum.
	 *
	 * Knowing this, we don't even need to examine the transport
	 * header checksum value; it is already accounted for in the
	 * checksum value found in the trailer.
	 */
	ip_payload_csum = csum_trailer->csum_value;

	pseudo_csum = csum_tcpudp_magic(ip4h->saddr, ip4h->daddr,
					ntohs(ip4h->tot_len) - ip4h->ihl * 4,
					ip4h->protocol, 0);

	/* The cast is required to ensure only the low 16 bits are examined */
	if (ip_payload_csum != (__sum16)~pseudo_csum) {
		priv->stats.csum_validation_failed++;
		return -EINVAL;
	}

	priv->stats.csum_ok++;
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int
rmnet_map_ipv6_dl_csum_trailer(struct sk_buff *skb,
			       struct rmnet_map_dl_csum_trailer *csum_trailer,
			       struct rmnet_priv *priv)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
	void *txporthdr = skb->data + sizeof(*ip6h);
	__sum16 *csum_field, pseudo_csum;
	__sum16 ip6_payload_csum;
	__be16 ip_header_csum;

	/* Checksum offload is only supported for UDP and TCP protocols;
	 * the packet cannot include any IPv6 extension headers
	 */
	csum_field = rmnet_map_get_csum_field(ip6h->nexthdr, txporthdr);
	if (!csum_field) {
		priv->stats.csum_err_invalid_transport++;
		return -EPROTONOSUPPORT;
	}

	/* The checksum value in the trailer is computed over the entire
	 * IP packet, including the IP header and payload.  To derive the
	 * transport checksum from this, we first subract the contribution
	 * of the IP header from the trailer checksum.  We then add the
	 * checksum computed over the pseudo header.
	 */
	ip_header_csum = (__force __be16)ip_fast_csum(ip6h, sizeof(*ip6h) / 4);
	ip6_payload_csum = csum16_sub(csum_trailer->csum_value, ip_header_csum);

	pseudo_csum = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
				      ntohs(ip6h->payload_len),
				      ip6h->nexthdr, 0);

	/* It's sufficient to compare the IP payload checksum with the
	 * negated pseudo checksum to determine whether the packet
	 * checksum was good.  (See further explanation in comments
	 * in rmnet_map_ipv4_dl_csum_trailer()).
	 *
	 * The cast is required to ensure only the low 16 bits are
	 * examined.
	 */
	if (ip6_payload_csum != (__sum16)~pseudo_csum) {
		priv->stats.csum_validation_failed++;
		return -EINVAL;
	}

	priv->stats.csum_ok++;
	return 0;
}
#else
static int
rmnet_map_ipv6_dl_csum_trailer(struct sk_buff *skb,
			       struct rmnet_map_dl_csum_trailer *csum_trailer,
			       struct rmnet_priv *priv)
{
	return 0;
}
#endif

static void rmnet_map_complement_ipv4_txporthdr_csum_field(struct iphdr *ip4h)
{
	void *txphdr;
	u16 *csum;

	txphdr = (void *)ip4h + ip4h->ihl * 4;

	if (ip4h->protocol == IPPROTO_TCP || ip4h->protocol == IPPROTO_UDP) {
		csum = (u16 *)rmnet_map_get_csum_field(ip4h->protocol, txphdr);
		*csum = ~(*csum);
	}
}

static void
rmnet_map_ipv4_ul_csum_header(struct iphdr *iphdr,
			      struct rmnet_map_ul_csum_header *ul_header,
			      struct sk_buff *skb)
{
	u16 val;

	val = MAP_CSUM_UL_ENABLED_FLAG;
	if (iphdr->protocol == IPPROTO_UDP)
		val |= MAP_CSUM_UL_UDP_FLAG;
	val |= skb->csum_offset & MAP_CSUM_UL_OFFSET_MASK;

	ul_header->csum_start_offset = htons(skb_network_header_len(skb));
	ul_header->csum_info = htons(val);

	skb->ip_summed = CHECKSUM_NONE;

	rmnet_map_complement_ipv4_txporthdr_csum_field(iphdr);
}

#if IS_ENABLED(CONFIG_IPV6)
static void
rmnet_map_complement_ipv6_txporthdr_csum_field(struct ipv6hdr *ip6h)
{
	void *txphdr;
	u16 *csum;

	txphdr = ip6h + 1;

	if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP) {
		csum = (u16 *)rmnet_map_get_csum_field(ip6h->nexthdr, txphdr);
		*csum = ~(*csum);
	}
}

static void
rmnet_map_ipv6_ul_csum_header(struct ipv6hdr *ipv6hdr,
			      struct rmnet_map_ul_csum_header *ul_header,
			      struct sk_buff *skb)
{
	u16 val;

	val = MAP_CSUM_UL_ENABLED_FLAG;
	if (ipv6hdr->nexthdr == IPPROTO_UDP)
		val |= MAP_CSUM_UL_UDP_FLAG;
	val |= skb->csum_offset & MAP_CSUM_UL_OFFSET_MASK;

	ul_header->csum_start_offset = htons(skb_network_header_len(skb));
	ul_header->csum_info = htons(val);

	skb->ip_summed = CHECKSUM_NONE;

	rmnet_map_complement_ipv6_txporthdr_csum_field(ipv6hdr);
}
#else
static void
rmnet_map_ipv6_ul_csum_header(void *ip6hdr,
			      struct rmnet_map_ul_csum_header *ul_header,
			      struct sk_buff *skb)
{
}
#endif

static void rmnet_map_v5_checksum_uplink_packet(struct sk_buff *skb,
						struct rmnet_port *port,
						struct net_device *orig_dev)
{
	struct rmnet_priv *priv = netdev_priv(orig_dev);
	struct rmnet_map_v5_csum_header *ul_header;

	ul_header = skb_push(skb, sizeof(*ul_header));
	memset(ul_header, 0, sizeof(*ul_header));
	ul_header->header_info = u8_encode_bits(RMNET_MAP_HEADER_TYPE_CSUM_OFFLOAD,
						MAPV5_HDRINFO_HDR_TYPE_FMASK);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		void *iph = ip_hdr(skb);
		__sum16 *check;
		void *trans;
		u8 proto;

		if (skb->protocol == htons(ETH_P_IP)) {
			u16 ip_len = ((struct iphdr *)iph)->ihl * 4;

			proto = ((struct iphdr *)iph)->protocol;
			trans = iph + ip_len;
		} else if (IS_ENABLED(CONFIG_IPV6) &&
			   skb->protocol == htons(ETH_P_IPV6)) {
			u16 ip_len = sizeof(struct ipv6hdr);

			proto = ((struct ipv6hdr *)iph)->nexthdr;
			trans = iph + ip_len;
		} else {
			priv->stats.csum_err_invalid_ip_version++;
			goto sw_csum;
		}

		check = rmnet_map_get_csum_field(proto, trans);
		if (check) {
			skb->ip_summed = CHECKSUM_NONE;
			/* Ask for checksum offloading */
			ul_header->csum_info |= MAPV5_CSUMINFO_VALID_FLAG;
			priv->stats.csum_hw++;
			return;
		}
	}

sw_csum:
	priv->stats.csum_sw++;
}

/* Adds MAP header to front of skb->data
 * Padding is calculated and set appropriately in MAP header. Mux ID is
 * initialized to 0.
 */
struct rmnet_map_header *rmnet_map_add_map_header(struct sk_buff *skb,
						  int hdrlen,
						  u32 data_format,
						  int pad)
{
	struct rmnet_map_header *map_header;
	u32 padding, map_datalen;

	map_datalen = skb->len - hdrlen;
	map_header = (struct rmnet_map_header *)
			skb_push(skb, sizeof(struct rmnet_map_header));
	memset(map_header, 0, sizeof(struct rmnet_map_header));

	/* Set next_hdr bit for csum offload packets */
	if (data_format & RMNET_FLAGS_EGRESS_MAP_CKSUMV5)
		map_header->flags |= MAP_NEXT_HEADER_FLAG;

	if (pad == RMNET_MAP_NO_PAD_BYTES) {
		map_header->pkt_len = htons(map_datalen);
		return map_header;
	}

	BUILD_BUG_ON(MAP_PAD_LEN_MASK < 3);
	padding = ALIGN(map_datalen, 4) - map_datalen;

	if (padding == 0)
		goto done;

	if (skb_tailroom(skb) < padding)
		return NULL;

	skb_put_zero(skb, padding);

done:
	map_header->pkt_len = htons(map_datalen + padding);
	/* This is a data packet, so the CMD bit is 0 */
	map_header->flags = padding & MAP_PAD_LEN_MASK;

	return map_header;
}

u32 rmnet_map_validate_packet_len(struct sk_buff *skb, u32 data_format)
{
	struct rmnet_map_v5_csum_header *next_hdr = NULL;
	struct rmnet_map_header *maph;
	u32 packet_len;
	u8 hdr_type;

	if (skb->len < sizeof(*maph))
		return 0;

	maph = (struct rmnet_map_header *)skb->data;

	/* Some hardware can send us empty frames. Catch them */
	if (!maph->pkt_len)
		return 0;

	packet_len = ntohs(maph->pkt_len) + sizeof(*maph);

	if (data_format & RMNET_FLAGS_INGRESS_MAP_CKSUMV4) {
		packet_len += sizeof(struct rmnet_map_dl_csum_trailer);
	} else if ((data_format &
		    (RMNET_FLAGS_INGRESS_MAP_CKSUMV5 | RMNET_FLAGS_INGRESS_COALESCE)) &&
		   !(maph->flags & MAP_CMD_FLAG)) {
		if (!(maph->flags & MAP_NEXT_HEADER_FLAG))
			return 0;

		if (skb->len < sizeof(*maph) + sizeof(*next_hdr))
			return 0;

		next_hdr = (struct rmnet_map_v5_csum_header *)(skb->data + sizeof(*maph));
		hdr_type = u8_get_bits(next_hdr->header_info,
				       MAPV5_HDRINFO_HDR_TYPE_FMASK);

		if (hdr_type == RMNET_MAP_HEADER_TYPE_CSUM_OFFLOAD)
			packet_len += sizeof(*next_hdr);
		else if (hdr_type != RMNET_MAP_HEADER_TYPE_COALESCING)
			return 0;
	}

	if (skb->len < packet_len)
		return 0;

	return packet_len;
}

/* Deaggregates a single packet
 * A whole new buffer is allocated for each portion of an aggregated frame.
 * Caller should keep calling deaggregate() on the source skb until 0 is
 * returned, indicating that there are no more packets to deaggregate. Caller
 * is responsible for freeing the original skb.
 */
struct sk_buff *rmnet_map_deaggregate(struct sk_buff *skb,
				      u32 data_format)
{
	struct sk_buff *skbn;
	u32 packet_len;

	packet_len = rmnet_map_validate_packet_len(skb, data_format);
	if (!packet_len)
		return NULL;

	skbn = alloc_skb(packet_len + RMNET_MAP_DEAGGR_SPACING, GFP_ATOMIC);
	if (!skbn)
		return NULL;

	skbn->dev = skb->dev;
	skb_reserve(skbn, RMNET_MAP_DEAGGR_HEADROOM);
	skb_put(skbn, packet_len);
	memcpy(skbn->data, skb->data, packet_len);
	skb_pull(skb, packet_len);

	return skbn;
}

/* Validates packet checksums. Function takes a pointer to
 * the beginning of a buffer which contains the IP payload +
 * padding + checksum trailer.
 * Only IPv4 and IPv6 are supported along with TCP & UDP.
 * Fragmented or tunneled packets are not supported.
 */
int rmnet_map_checksum_downlink_packet(struct sk_buff *skb, u16 len)
{
	struct rmnet_priv *priv = netdev_priv(skb->dev);
	struct rmnet_map_dl_csum_trailer *csum_trailer;

	if (unlikely(!(skb->dev->features & NETIF_F_RXCSUM))) {
		priv->stats.csum_sw++;
		return -EOPNOTSUPP;
	}

	csum_trailer = (struct rmnet_map_dl_csum_trailer *)(skb->data + len);

	if (!(csum_trailer->flags & MAP_CSUM_DL_VALID_FLAG)) {
		priv->stats.csum_valid_unset++;
		return -EINVAL;
	}

	if (skb->protocol == htons(ETH_P_IP))
		return rmnet_map_ipv4_dl_csum_trailer(skb, csum_trailer, priv);

	if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6))
		return rmnet_map_ipv6_dl_csum_trailer(skb, csum_trailer, priv);

	priv->stats.csum_err_invalid_ip_version++;

	return -EPROTONOSUPPORT;
}

static void rmnet_map_v4_checksum_uplink_packet(struct sk_buff *skb,
						struct net_device *orig_dev)
{
	struct rmnet_priv *priv = netdev_priv(orig_dev);
	struct rmnet_map_ul_csum_header *ul_header;
	void *iphdr;

	ul_header = (struct rmnet_map_ul_csum_header *)
		    skb_push(skb, sizeof(struct rmnet_map_ul_csum_header));

	if (unlikely(!(orig_dev->features &
		     (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM))))
		goto sw_csum;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		goto sw_csum;

	iphdr = (char *)ul_header +
		sizeof(struct rmnet_map_ul_csum_header);

	if (skb->protocol == htons(ETH_P_IP)) {
		rmnet_map_ipv4_ul_csum_header(iphdr, ul_header, skb);
		priv->stats.csum_hw++;
		return;
	}

	if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6)) {
		rmnet_map_ipv6_ul_csum_header(iphdr, ul_header, skb);
		priv->stats.csum_hw++;
		return;
	}

	priv->stats.csum_err_invalid_ip_version++;

sw_csum:
	memset(ul_header, 0, sizeof(*ul_header));

	priv->stats.csum_sw++;
}

/* Generates UL checksum meta info header for IPv4 and IPv6 over TCP and UDP
 * packets that are supported for UL checksum offload.
 */
void rmnet_map_checksum_uplink_packet(struct sk_buff *skb,
				      struct rmnet_port *port,
				      struct net_device *orig_dev,
				      int csum_type)
{
	switch (csum_type) {
	case RMNET_FLAGS_EGRESS_MAP_CKSUMV4:
		rmnet_map_v4_checksum_uplink_packet(skb, orig_dev);
		break;
	case RMNET_FLAGS_EGRESS_MAP_CKSUMV5:
		rmnet_map_v5_checksum_uplink_packet(skb, port, orig_dev);
		break;
	default:
		break;
	}
}

static struct rmnet_map_v5_csum_header *
rmnet_map_get_next_hdr(struct sk_buff *skb)
{
	return (struct rmnet_map_v5_csum_header *)(skb->data +
						   sizeof(struct rmnet_map_header));
}

static u8 rmnet_map_get_next_hdr_type(struct sk_buff *skb)
{
	struct rmnet_map_v5_csum_header *hdr = rmnet_map_get_next_hdr(skb);

	return u8_get_bits(hdr->header_info, MAPV5_HDRINFO_HDR_TYPE_FMASK);
}

static bool rmnet_map_get_csum_valid(struct sk_buff *skb)
{
	struct rmnet_map_v5_csum_header *hdr = rmnet_map_get_next_hdr(skb);

	return !!(hdr->csum_info & MAPV5_CSUMINFO_VALID_FLAG);
}

/* Stamp GSO metadata so the network stack can segment a coalesced SKB. */
static void rmnet_map_gso_stamp(struct sk_buff *skb,
				struct rmnet_map_coal_metadata *coal_meta)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);

	if (coal_meta->trans_proto == IPPROTO_TCP)
		shinfo->gso_type = (coal_meta->ip_proto == 4) ?
				   SKB_GSO_TCPV4 : SKB_GSO_TCPV6;
	else
		shinfo->gso_type = SKB_GSO_UDP_L4;

	shinfo->gso_size = coal_meta->data_len;
	shinfo->gso_segs = coal_meta->pkt_count;
}

/* Set the transport checksum to the pseudo-header checksum and request
 * partial checksum offload, letting the NIC or stack finish it.
 */
static void rmnet_map_partial_csum(struct sk_buff *skb,
				   struct rmnet_map_coal_metadata *coal_meta)
{
	u16 pkt_len = skb->len - coal_meta->ip_len;
	unsigned char *data = skb->data;
	__sum16 pseudo;

	if (coal_meta->ip_proto == 4) {
		struct iphdr *iph = (struct iphdr *)data;

		pseudo = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
					    pkt_len, coal_meta->trans_proto, 0);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)data;

		pseudo = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					  pkt_len, coal_meta->trans_proto, 0);
	}

	if (coal_meta->trans_proto == IPPROTO_TCP) {
		struct tcphdr *tp = (struct tcphdr *)(data + coal_meta->ip_len);

		tp->check = pseudo;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		struct udphdr *up = (struct udphdr *)(data + coal_meta->ip_len);

		up->check = pseudo;
		skb->csum_offset = offsetof(struct udphdr, check);
	}

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb->data + coal_meta->ip_len - skb->head;
}

/* On some hardware, num_nlos in the coalescing header can be reported
 * incorrectly under certain conditions even though the per-NLO num_packets
 * fields it is meant to summarize are correct. Recompute the true NLO count
 * directly from the nl_pairs[] content rather than trusting the declared
 * value, so that rmnet_map_v5_csum_fixup()'s single NLO, single packet check
 * is reliable.
 */
static void rmnet_map_v5_fixup_num_nlos(struct rmnet_map_v5_coal_header *coal_hdr)
{
	u8 nlos = 0;
	int i;

	for (i = 0; i < RMNET_MAP_V5_MAX_NLOS; i++) {
		if (coal_hdr->nl_pairs[i].num_packets)
			nlos++;
	}

	coal_hdr->coal_info = u8_encode_bits(nlos, MAPV5_COALINFO_NUM_NLOS_FMASK) |
			      (coal_hdr->coal_info & MAPV5_COALINFO_CSUM_VALID_FLAG);
}

/* The checksum valid indication for a single NLO, single packet coalescing
 * frame cannot be trusted when the close reason is a TCP FIN/PSH, a packet
 * count limit, a byte count limit or a time limit.
 */
static bool rmnet_map_v5_csum_fixup(struct rmnet_map_v5_coal_header *coal_hdr)
{
	u8 close_value = u8_get_bits(coal_hdr->close_info,
				     MAPV5_CLOSEINFO_CLOSE_VALUE_FMASK);
	u8 close_type = u8_get_bits(coal_hdr->close_info,
				    MAPV5_CLOSEINFO_CLOSE_TYPE_FMASK);
	u8 num_nlos = u8_get_bits(coal_hdr->coal_info,
				  MAPV5_COALINFO_NUM_NLOS_FMASK);

	/* Only applies to single NLO, single packet frames */
	if (num_nlos != 1 || coal_hdr->nl_pairs[0].num_packets != 1)
		return false;

	/* TCP FIN or PSH triggered the close */
	if (close_type == RMNET_MAP_COAL_CLOSE_COAL)
		return true;

	/* Hit a hardware limit */
	if (close_type == RMNET_MAP_COAL_CLOSE_HW) {
		switch (close_value) {
		case RMNET_MAP_COAL_CLOSE_HW_PKT:
		case RMNET_MAP_COAL_CLOSE_HW_BYTE:
		case RMNET_MAP_COAL_CLOSE_HW_TIME:
			return true;
		}
	}

	return false;
}

/* Carve one logical segment from a coalesced SKB and append it to the list.
 * Adjusts TCP sequence numbers, IP IDs/lengths, and checksum state.
 */
static void
__rmnet_map_segment_coal_skb(struct sk_buff *coal_skb,
			     struct rmnet_map_coal_metadata *coal_meta,
			     struct sk_buff_head *list, u8 pkt_id,
			     bool csum_valid)
{
	u32 dlen = coal_meta->data_len * coal_meta->pkt_count;
	struct rmnet_priv *priv = netdev_priv(coal_skb->dev);
	u32 hlen = coal_meta->ip_len + coal_meta->trans_len;
	struct sk_buff *skbn;

	/* RFC 768: UDP checksum is optional for IPv4, and is 0 if unused.
	 * Such packets are never actually bad, regardless of what the
	 * checksum bitmap says.
	 */
	if (!csum_valid && coal_meta->zero_csum)
		csum_valid = true;

	if (!csum_valid) {
		priv->stats.coal_csum_drop++;
		goto next_pkt;
	}

	skbn = alloc_skb(hlen + dlen + RMNET_MAP_DEAGGR_HEADROOM, GFP_ATOMIC);
	if (!skbn)
		goto next_pkt;

	skb_reserve(skbn, hlen + RMNET_MAP_DEAGGR_HEADROOM);
	skb_put_data(skbn,
		     coal_skb->data + coal_meta->ip_len + coal_meta->trans_len +
		     coal_meta->data_offset,
		     dlen);

	/* Restore transport header */
	skb_push(skbn, coal_meta->trans_len);
	memcpy(skbn->data, coal_meta->trans_header, coal_meta->trans_len);
	skb_reset_transport_header(skbn);

	if (coal_meta->trans_proto == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skbn);

		th->seq = htonl(ntohl(th->seq) + coal_meta->data_offset);
		/* Strip dangerous flags from non-final segments */
		if ((th->fin || th->psh) &&
		    hlen + coal_meta->data_offset + dlen < coal_skb->len) {
			th->fin = 0;
			th->psh = 0;
		}
	} else if (coal_meta->trans_proto == IPPROTO_UDP) {
		struct udphdr *uh = udp_hdr(skbn);

		uh->len = htons(skbn->len);
	}

	/* Restore IP header */
	skb_push(skbn, coal_meta->ip_len);
	memcpy(skbn->data, coal_meta->ip_header, coal_meta->ip_len);
	skb_reset_network_header(skbn);

	if (coal_meta->ip_proto == 4) {
		struct iphdr *iph = ip_hdr(skbn);

		iph->id = htons(ntohs(iph->id) + pkt_id);
		iph->tot_len = htons(skbn->len);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
	} else {
		ipv6_hdr(skbn)->payload_len =
			htons(skbn->len - sizeof(struct ipv6hdr));
	}

	rmnet_map_partial_csum(skbn, coal_meta);

	skbn->dev = coal_skb->dev;
	priv->stats.coal_reconstruct++;

	if (coal_meta->pkt_count > 1)
		rmnet_map_gso_stamp(skbn, coal_meta);

	__skb_queue_tail(list, skbn);

next_pkt:
	coal_meta->data_offset += dlen;
	coal_meta->pkt_count = 0;
}

/* Parse the IP header of the coalesced frame and perform basic
 * validation of header fields.
 */
static bool rmnet_map_coal_parse_ip_hdr(struct sk_buff *coal_skb,
					struct rmnet_map_coal_metadata *meta,
					bool *gro)
{
	struct rmnet_priv *priv = netdev_priv(coal_skb->dev);
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__be16 frag_off;
	u8 protocol;
	int ret;

	if (coal_skb->len < sizeof(*iph)) {
		priv->stats.coal_ip_invalid++;
		return false;
	}

	iph = (struct iphdr *)coal_skb->data;

	if (iph->version == 4) {
		meta->ip_proto = 4;
		meta->ip_len = iph->ihl * 4;
		meta->trans_proto = iph->protocol;
		meta->ip_header = iph;
		if (meta->ip_len < sizeof(*iph) || coal_skb->len < meta->ip_len) {
			priv->stats.coal_ip_invalid++;
			return false;
		}

		if (ip_is_fragment(iph)) {
			priv->stats.coal_ip_invalid++;
			return false;
		}

		if (iph->ihl != 5)
			*gro = false;
	} else if (iph->version == 6) {
		if (coal_skb->len < sizeof(*ip6h)) {
			priv->stats.coal_ip_invalid++;
			return false;
		}

		ip6h = (struct ipv6hdr *)iph;
		protocol = ip6h->nexthdr;
		meta->ip_proto = 6;
		ret = ipv6_skip_exthdr(coal_skb, sizeof(*ip6h), &protocol,
				       &frag_off);
		if (ret < 0 || frag_off) {
			priv->stats.coal_ip_invalid++;
			return false;
		}

		meta->ip_len = (u16)ret;
		meta->trans_proto = protocol;
		meta->ip_header = ip6h;
		if (meta->ip_len > sizeof(*ip6h))
			*gro = false;
	} else {
		priv->stats.coal_ip_invalid++;
		return false;
	}

	return true;
}

/* Parse the transport header following the IP header into coal_meta. The
 * available length is checked before any field is read.
 */
static bool rmnet_map_coal_parse_trans_hdr(struct sk_buff *coal_skb,
					   struct rmnet_map_coal_metadata *meta)
{
	struct rmnet_priv *priv = netdev_priv(coal_skb->dev);
	struct udphdr *uh;
	struct tcphdr *th;
	u32 avail;
	u8 *base;

	base = (u8 *)meta->ip_header + meta->ip_len;
	avail = coal_skb->len - meta->ip_len;

	if (meta->trans_proto == IPPROTO_TCP) {
		if (avail < sizeof(*th)) {
			priv->stats.coal_trans_invalid++;
			return false;
		}

		th = (struct tcphdr *)base;
		meta->trans_len = th->doff * 4;
		meta->trans_header = th;
		if (meta->trans_len < sizeof(*th) || avail < meta->trans_len) {
			priv->stats.coal_trans_invalid++;
			return false;
		}
	} else if (meta->trans_proto == IPPROTO_UDP) {
		if (avail < sizeof(*uh)) {
			priv->stats.coal_trans_invalid++;
			return false;
		}

		uh = (struct udphdr *)base;
		meta->trans_len = sizeof(*uh);
		meta->trans_header = uh;
		if (meta->ip_proto == 4 && !uh->check)
			meta->zero_csum = true;
	} else {
		priv->stats.coal_trans_invalid++;
		return false;
	}

	return true;
}

/* Reject the frame if the total data bytes claimed by all NLOs exceed
 * the actual payload in the SKB.  Each pkt_len covers IP+transport
 * headers plus per-packet data. Headers appear once, so subtract hlen
 * per packet and check the running sum against available data.
 */
static bool rmnet_map_coal_validate_bounds(struct sk_buff *coal_skb,
					   struct rmnet_map_v5_coal_header *coal_hdr,
					   u8 num_nlos, u32 hlen)
{
	u32 total_data = 0;
	u32 nlo_len;
	u16 plen;
	u8 i;

	for (i = 0; i < num_nlos; i++) {
		plen = ntohs(coal_hdr->nl_pairs[i].pkt_len);

		if (plen < hlen)
			return false;

		nlo_len = (u32)(plen - hlen) * coal_hdr->nl_pairs[i].num_packets;
		if (total_data + nlo_len > coal_skb->len - hlen)
			return false;

		total_data += nlo_len;
	}

	return true;
}

/* Attempt the GRO-friendly fast path for a single-NLO, checksum-valid frame
 * by reusing the original SKB and stamping GSO metadata instead of copying
 * out each segment.  Returns true if the frame was consumed via the fast
 * path, or false if the caller should fall back to full segmentation.
 */
static bool rmnet_map_coal_gro_fast_path(struct sk_buff *coal_skb,
					 struct rmnet_map_v5_coal_header *coal_hdr,
					 struct rmnet_map_coal_metadata *coal_meta,
					 struct sk_buff_head *list,
					 u8 num_nlos, bool gro)
{
	u32 hlen = coal_meta->ip_len + coal_meta->trans_len;

	if (!gro || num_nlos != 1 ||
	    !(coal_hdr->coal_info & MAPV5_COALINFO_CSUM_VALID_FLAG))
		return false;

	coal_meta->data_len = ntohs(coal_hdr->nl_pairs[0].pkt_len) - hlen;
	coal_meta->pkt_count = coal_hdr->nl_pairs[0].num_packets;

	coal_skb->ip_summed = CHECKSUM_UNNECESSARY;
	if (coal_meta->pkt_count > 1) {
		rmnet_map_partial_csum(coal_skb, coal_meta);
		rmnet_map_gso_stamp(coal_skb, coal_meta);
	}

	__skb_queue_tail(list, coal_skb);
	return true;
}

/* NLO packet lengths are already bounds-checked by
 * rmnet_map_coal_validate_bounds() so no further validation is needed here.
 */
static void rmnet_map_coal_segment_loop(struct sk_buff *coal_skb,
					struct rmnet_map_v5_coal_header *coal_hdr,
					struct rmnet_map_coal_metadata *coal_meta,
					struct sk_buff_head *list,
					u64 nlo_err_mask, bool gro, u8 num_nlos)
{
	struct rmnet_priv *priv = netdev_priv(coal_skb->dev);
	u32 hlen = coal_meta->ip_len + coal_meta->trans_len;
	u8 pkt, total_pkt = 0;
	bool csum_err;
	u16 pkt_len;
	u8 nlo;

	for (nlo = 0; nlo < num_nlos; nlo++) {
		pkt_len = ntohs(coal_hdr->nl_pairs[nlo].pkt_len);
		pkt_len -= hlen;
		coal_meta->data_len = pkt_len;

		/* nlo_err_mask is one flat bitstream across all NLOs. Shift
		 * it once per packet in absolute frame order and do not
		 * re-align at the NLO boundary above. See the comment on
		 * rmnet_map_data_check_coal_header() for why.
		 */
		for (pkt = 0; pkt < coal_hdr->nl_pairs[nlo].num_packets;
		     pkt++, total_pkt++, nlo_err_mask >>= 1) {
			csum_err = nlo_err_mask & 1;

			if (csum_err)
				priv->stats.coal_csum_err++;

			if (!gro) {
				coal_meta->pkt_count = 1;
				__rmnet_map_segment_coal_skb(coal_skb, coal_meta,
							     list, total_pkt,
							     !csum_err);
				continue;
			}

			if (csum_err) {
				if (coal_meta->pkt_count)
					__rmnet_map_segment_coal_skb(coal_skb,
								     coal_meta,
								     list,
								     total_pkt,
								     true);
				coal_meta->pkt_count = 1;
				__rmnet_map_segment_coal_skb(coal_skb, coal_meta,
							     list, total_pkt,
							     false);
			} else {
				coal_meta->pkt_count++;
			}
		}

		/* Flush remaining packets from this NLO */
		if (coal_meta->pkt_count)
			__rmnet_map_segment_coal_skb(coal_skb, coal_meta, list,
						     total_pkt, true);
	}
}

/* Expand a coalesced SKB into individual IP packets placed on the list.
 * NLOs with checksum errors are dropped. __rmnet_map_ingress_handler will
 * free the SKB in the error case.
 */
static int rmnet_map_segment_coal_skb(struct sk_buff *coal_skb,
				      u64 nlo_err_mask,
				      struct sk_buff_head *list,
				      u16 len)
{
	bool gro = coal_skb->dev->features & NETIF_F_GRO_HW;
	struct rmnet_map_v5_coal_header *coal_hdr;
	struct rmnet_map_coal_metadata coal_meta;
	u8 num_nlos;
	u32 hlen;

	memset(&coal_meta, 0, sizeof(coal_meta));

	/* Drop any MAP frame padding. The coal header is counted in len */
	skb_pull(coal_skb, sizeof(struct rmnet_map_header));
	skb_trim(coal_skb, len);
	coal_hdr = (struct rmnet_map_v5_coal_header *)coal_skb->data;
	rmnet_map_v5_fixup_num_nlos(coal_hdr);
	num_nlos = u8_get_bits(coal_hdr->coal_info, MAPV5_COALINFO_NUM_NLOS_FMASK);
	skb_pull(coal_skb, sizeof(*coal_hdr));

	if (!rmnet_map_coal_parse_ip_hdr(coal_skb, &coal_meta, &gro))
		return -EINVAL;

	if (!rmnet_map_coal_parse_trans_hdr(coal_skb, &coal_meta))
		return -EINVAL;

	hlen = coal_meta.ip_len + coal_meta.trans_len;

	if (!rmnet_map_coal_validate_bounds(coal_skb, coal_hdr, num_nlos, hlen))
		return -EINVAL;

	if (rmnet_map_v5_csum_fixup(coal_hdr) && !coal_meta.zero_csum) {
		coal_skb->ip_summed = CHECKSUM_NONE;
		__skb_queue_tail(list, coal_skb);
		return 0;
	}

	if (rmnet_map_coal_gro_fast_path(coal_skb, coal_hdr, &coal_meta, list,
					 num_nlos, gro))
		return 0;

	rmnet_map_coal_segment_loop(coal_skb, coal_hdr, &coal_meta, list,
				    nlo_err_mask, gro, num_nlos);

	return 0;
}

/* Log the hardware close-reason counter for a coalescing header. */
static void rmnet_map_data_log_close_stats(struct rmnet_priv *priv,
					   u8 type, u8 code)
{
	switch (type) {
	case RMNET_MAP_COAL_CLOSE_NON_COAL:
		priv->stats.coal_close_non_coal++;
		break;
	case RMNET_MAP_COAL_CLOSE_IP_MISS:
		priv->stats.coal_close_ip_miss++;
		break;
	case RMNET_MAP_COAL_CLOSE_TRANS_MISS:
		priv->stats.coal_close_trans_miss++;
		break;
	case RMNET_MAP_COAL_CLOSE_HW:
		switch (code) {
		case RMNET_MAP_COAL_CLOSE_HW_NL:
			priv->stats.coal_close_hw_nl++;
			break;
		case RMNET_MAP_COAL_CLOSE_HW_PKT:
			priv->stats.coal_close_hw_pkt++;
			break;
		case RMNET_MAP_COAL_CLOSE_HW_BYTE:
			priv->stats.coal_close_hw_byte++;
			break;
		case RMNET_MAP_COAL_CLOSE_HW_TIME:
			priv->stats.coal_close_hw_time++;
			break;
		case RMNET_MAP_COAL_CLOSE_HW_EVICT:
			priv->stats.coal_close_hw_evict++;
			break;
		default:
			break;
		}
		break;
	case RMNET_MAP_COAL_CLOSE_COAL:
		priv->stats.coal_close_coal++;
		break;
	default:
		break;
	}
}

/* Validate the coalescing header and build the checksum error mask.
 *
 * Checks performed:
 *  - MAP pkt_len accommodates the coal header (coal header is counted in
 *    pkt_len. pkt_len < sizeof(*coal_hdr) means no payload is possible).
 *  - num_nlos is in [1, RMNET_MAP_V5_MAX_NLOS].
 *  - Total packet count does not exceed RMNET_MAP_V5_MAX_PACKETS.
 *
 * nlo_err_mask is NOT six independent per-NLO bitmaps. Each nl_pairs
 * slot only has room for an 8 bit csum_error_bitmap, but a single NLO
 * can carry more than 8 packets (up to RMNET_MAP_V5_MAX_PACKETS), so
 * hardware spills a wide NLO's error bits into the csum_error_bitmap
 * bytes of the following slots rather than truncating them. The
 * six bitmap bytes are therefore always concatenated in slot order
 * into one flat RMNET_MAP_V5_MAX_NLOS * 8 = RMNET_MAP_V5_MAX_PACKETS
 * bit value, addressed by a packet's absolute position in the frame,
 * regardless of how many NLOs are actually in use. Receivers must
 * walk it as a single contiguous stream and must not expect it to
 * align it at NLO boundaries.
 */
static int rmnet_map_data_check_coal_header(struct sk_buff *skb,
					    u64 *nlo_err_mask)
{
	struct rmnet_map_header *maph = (struct rmnet_map_header *)skb->data;
	struct rmnet_priv *priv = netdev_priv(skb->dev);
	struct rmnet_map_v5_coal_header *coal_hdr;
	u8 num_nlos, pkts = 0;
	u64 mask = 0;
	int i;

	/* coal header is counted in pkt_len */
	if (ntohs(maph->pkt_len) < sizeof(*coal_hdr)) {
		priv->stats.coal_hdr_nlo_err++;
		return -EINVAL;
	}

	coal_hdr = (struct rmnet_map_v5_coal_header *)(skb->data + sizeof(*maph));
	num_nlos = u8_get_bits(coal_hdr->coal_info, MAPV5_COALINFO_NUM_NLOS_FMASK);

	if (num_nlos == 0 || num_nlos > RMNET_MAP_V5_MAX_NLOS) {
		priv->stats.coal_hdr_nlo_err++;
		return -EINVAL;
	}

	for (i = 0; i < RMNET_MAP_V5_MAX_NLOS; i++) {
		u8 err = coal_hdr->nl_pairs[i].csum_error_bitmap;
		u8 pkt = coal_hdr->nl_pairs[i].num_packets;

		mask |= ((u64)err) << (8 * i);
		pkts += pkt;
		if (pkts > RMNET_MAP_V5_MAX_PACKETS) {
			priv->stats.coal_hdr_pkt_err++;
			return -EINVAL;
		}
	}

	priv->stats.coal_pkts += pkts;
	rmnet_map_data_log_close_stats(priv,
				       u8_get_bits(coal_hdr->close_info,
						   MAPV5_CLOSEINFO_CLOSE_TYPE_FMASK),
				       u8_get_bits(coal_hdr->close_info,
						   MAPV5_CLOSEINFO_CLOSE_VALUE_FMASK));

	*nlo_err_mask = mask;
	return 0;
}

int rmnet_map_process_next_hdr_packet(struct sk_buff *skb,
				      struct sk_buff_head *list,
				      u16 len, u32 data_format)
{
	struct rmnet_priv *priv = netdev_priv(skb->dev);
	u64 nlo_err_mask;
	int rc;

	switch (rmnet_map_get_next_hdr_type(skb)) {
	case RMNET_MAP_HEADER_TYPE_COALESCING:
		if (!(data_format & RMNET_FLAGS_INGRESS_COALESCE))
			return -EINVAL;

		priv->stats.coal_rx++;
		rc = rmnet_map_data_check_coal_header(skb, &nlo_err_mask);
		if (rc)
			return rc;

		rc = rmnet_map_segment_coal_skb(skb, nlo_err_mask, list, len);
		if (rc)
			return rc;

		if (skb_peek(list) != skb)
			consume_skb(skb);
		break;

	case RMNET_MAP_HEADER_TYPE_CSUM_OFFLOAD:
		if (unlikely(!(skb->dev->features & NETIF_F_RXCSUM))) {
			priv->stats.csum_sw++;
		} else if (rmnet_map_get_csum_valid(skb)) {
			priv->stats.csum_ok++;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		} else {
			priv->stats.csum_valid_unset++;
		}

		skb_pull(skb, sizeof(struct rmnet_map_header) +
			      sizeof(struct rmnet_map_v5_csum_header));
		skb_trim(skb, len);
		__skb_queue_tail(list, skb);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

#define RMNET_AGG_BYPASS_TIME_NSEC 10000000L

static void reset_aggr_params(struct rmnet_port *port)
{
	port->skbagg_head = NULL;
	port->agg_count = 0;
	port->agg_state = 0;
	memset(&port->agg_time, 0, sizeof(struct timespec64));
}

static void rmnet_send_skb(struct rmnet_port *port, struct sk_buff *skb)
{
	if (skb_needs_linearize(skb, port->dev->features)) {
		if (unlikely(__skb_linearize(skb))) {
			struct rmnet_priv *priv;

			priv = netdev_priv(port->rmnet_dev);
			this_cpu_inc(priv->pcpu_stats->stats.tx_drops);
			dev_kfree_skb_any(skb);
			return;
		}
	}

	dev_queue_xmit(skb);
}

static void rmnet_map_flush_tx_packet_work(struct work_struct *work)
{
	struct sk_buff *skb = NULL;
	struct rmnet_port *port;

	port = container_of(work, struct rmnet_port, agg_wq);

	spin_lock_bh(&port->agg_lock);
	if (likely(port->agg_state == -EINPROGRESS)) {
		/* Buffer may have already been shipped out */
		if (likely(port->skbagg_head)) {
			skb = port->skbagg_head;
			reset_aggr_params(port);
		}
		port->agg_state = 0;
	}

	spin_unlock_bh(&port->agg_lock);
	if (skb)
		rmnet_send_skb(port, skb);
}

static enum hrtimer_restart rmnet_map_flush_tx_packet_queue(struct hrtimer *t)
{
	struct rmnet_port *port;

	port = container_of(t, struct rmnet_port, hrtimer);

	schedule_work(&port->agg_wq);

	return HRTIMER_NORESTART;
}

unsigned int rmnet_map_tx_aggregate(struct sk_buff *skb, struct rmnet_port *port,
				    struct net_device *orig_dev)
{
	struct timespec64 diff, last;
	unsigned int len = skb->len;
	struct sk_buff *agg_skb;
	int size;

	spin_lock_bh(&port->agg_lock);
	memcpy(&last, &port->agg_last, sizeof(struct timespec64));
	ktime_get_real_ts64(&port->agg_last);

	if (!port->skbagg_head) {
		/* Check to see if we should agg first. If the traffic is very
		 * sparse, don't aggregate.
		 */
new_packet:
		diff = timespec64_sub(port->agg_last, last);
		size = port->egress_agg_params.bytes - skb->len;

		if (size < 0) {
			/* dropped */
			spin_unlock_bh(&port->agg_lock);
			return 0;
		}

		if (diff.tv_sec > 0 || diff.tv_nsec > RMNET_AGG_BYPASS_TIME_NSEC ||
		    size == 0)
			goto no_aggr;

		port->skbagg_head = skb_copy_expand(skb, 0, size, GFP_ATOMIC);
		if (!port->skbagg_head)
			goto no_aggr;

		dev_kfree_skb_any(skb);
		port->skbagg_head->protocol = htons(ETH_P_MAP);
		port->agg_count = 1;
		ktime_get_real_ts64(&port->agg_time);
		skb_frag_list_init(port->skbagg_head);
		goto schedule;
	}
	diff = timespec64_sub(port->agg_last, port->agg_time);
	size = port->egress_agg_params.bytes - port->skbagg_head->len;

	if (skb->len > size) {
		agg_skb = port->skbagg_head;
		reset_aggr_params(port);
		spin_unlock_bh(&port->agg_lock);
		hrtimer_cancel(&port->hrtimer);
		rmnet_send_skb(port, agg_skb);
		spin_lock_bh(&port->agg_lock);
		goto new_packet;
	}

	if (skb_has_frag_list(port->skbagg_head))
		port->skbagg_tail->next = skb;
	else
		skb_shinfo(port->skbagg_head)->frag_list = skb;

	port->skbagg_head->len += skb->len;
	port->skbagg_head->data_len += skb->len;
	port->skbagg_head->truesize += skb->truesize;
	port->skbagg_tail = skb;
	port->agg_count++;

	if (diff.tv_sec > 0 || diff.tv_nsec > port->egress_agg_params.time_nsec ||
	    port->agg_count >= port->egress_agg_params.count ||
	    port->skbagg_head->len == port->egress_agg_params.bytes) {
		agg_skb = port->skbagg_head;
		reset_aggr_params(port);
		spin_unlock_bh(&port->agg_lock);
		hrtimer_cancel(&port->hrtimer);
		rmnet_send_skb(port, agg_skb);
		return len;
	}

schedule:
	if (!hrtimer_active(&port->hrtimer) && port->agg_state != -EINPROGRESS) {
		port->agg_state = -EINPROGRESS;
		hrtimer_start(&port->hrtimer,
			      ns_to_ktime(port->egress_agg_params.time_nsec),
			      HRTIMER_MODE_REL);
	}
	spin_unlock_bh(&port->agg_lock);

	return len;

no_aggr:
	spin_unlock_bh(&port->agg_lock);
	skb->protocol = htons(ETH_P_MAP);
	dev_queue_xmit(skb);

	return len;
}

void rmnet_map_update_ul_agg_config(struct rmnet_port *port, u32 size,
				    u32 count, u32 time)
{
	spin_lock_bh(&port->agg_lock);
	port->egress_agg_params.bytes = size;
	WRITE_ONCE(port->egress_agg_params.count, count);
	port->egress_agg_params.time_nsec = time * NSEC_PER_USEC;
	spin_unlock_bh(&port->agg_lock);
}

void rmnet_map_tx_aggregate_init(struct rmnet_port *port)
{
	hrtimer_setup(&port->hrtimer, rmnet_map_flush_tx_packet_queue, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
	spin_lock_init(&port->agg_lock);
	rmnet_map_update_ul_agg_config(port, 4096, 1, 800);
	INIT_WORK(&port->agg_wq, rmnet_map_flush_tx_packet_work);
}

void rmnet_map_tx_aggregate_exit(struct rmnet_port *port)
{
	hrtimer_cancel(&port->hrtimer);
	cancel_work_sync(&port->agg_wq);

	spin_lock_bh(&port->agg_lock);
	if (port->agg_state == -EINPROGRESS) {
		if (port->skbagg_head) {
			dev_kfree_skb_any(port->skbagg_head);
			reset_aggr_params(port);
		}

		port->agg_state = 0;
	}
	spin_unlock_bh(&port->agg_lock);
}
