/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019, Intel Corporation. */

#ifndef _ICE_TXRX_LIB_H_
#define _ICE_TXRX_LIB_H_
#include "ice.h"

/**
 * ice_test_staterr - tests bits in Rx descriptor status and error fields
 * @status_err_n: Rx descriptor status_error0 or status_error1 bits
 * @stat_err_bits: value to mask
 *
 * This function does some fast chicanery in order to return the
 * value of the mask which is really only used for boolean tests.
 * The status_error_len doesn't need to be shifted because it begins
 * at offset zero.
 */
static inline bool
ice_test_staterr(__le16 status_err_n, const u16 stat_err_bits)
{
	return !!(status_err_n & cpu_to_le16(stat_err_bits));
}

static inline __le64
ice_build_ctob(u64 td_cmd, u64 td_offset, unsigned int size, u64 td_tag)
{
	return cpu_to_le64(ICE_TX_DESC_DTYPE_DATA |
			   (td_cmd    << ICE_TXD_QW1_CMD_S) |
			   (td_offset << ICE_TXD_QW1_OFFSET_S) |
			   ((u64)size << ICE_TXD_QW1_TX_BUF_SZ_S) |
			   (td_tag    << ICE_TXD_QW1_L2TAG1_S));
}

/**
 * ice_get_vlan_tag_from_rx_desc - get VLAN from Rx flex descriptor
 * @rx_desc: Rx 32b flex descriptor with RXDID=2
 *
 * The OS and current PF implementation only support stripping a single VLAN tag
 * at a time, so there should only ever be 0 or 1 tags in the l2tag* fields. If
 * one is found return the tag, else return 0 to mean no VLAN tag was found.
 */
static inline u16
ice_get_vlan_tag_from_rx_desc(const union ice_32b_rx_flex_desc *rx_desc)
{
	u16 stat_err_bits;

	stat_err_bits = BIT(ICE_RX_FLEX_DESC_STATUS0_L2TAG1P_S);
	if (ice_test_staterr(rx_desc->wb.status_error0, stat_err_bits))
		return le16_to_cpu(rx_desc->wb.l2tag1);

	stat_err_bits = BIT(ICE_RX_FLEX_DESC_STATUS1_L2TAG2P_S);
	if (ice_test_staterr(rx_desc->wb.status_error1, stat_err_bits))
		return le16_to_cpu(rx_desc->wb.l2tag2_2nd);

	return 0;
}

/**
 * ice_receive_skb - Send a completed packet up the stack
 * @rx_ring: Rx ring in play
 * @skb: packet to send up
 *
 * This function sends the completed packet (via. skb) up the stack using
 * gro receive functions
 */
static inline void ice_receive_skb(const struct ice_rx_ring *rx_ring,
				   struct sk_buff *skb)
{
	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);

	/* send completed skb up the stack */
	napi_gro_receive(&rx_ring->q_vector->napi, skb);
}

/**
 * ice_xdp_ring_update_tail - Updates the XDP Tx ring tail register
 * @xdp_ring: XDP Tx ring
 *
 * This function updates the XDP Tx ring tail register.
 */
static inline void ice_xdp_ring_update_tail(struct ice_tx_ring *xdp_ring)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdp_ring->next_to_use, xdp_ring->tail);
}

void ice_finalize_xdp_rx(struct ice_tx_ring *xdp_ring, unsigned int xdp_res);
int ice_xmit_xdp_buff(struct xdp_buff *xdp, struct ice_tx_ring *xdp_ring);
int ice_xmit_xdp_ring(void *data, u16 size, struct ice_tx_ring *xdp_ring);
void ice_release_rx_desc(struct ice_rx_ring *rx_ring, u16 val);

void __ice_xdp_build_meta(struct xdp_meta_generic_rx *rx_md,
			  const union ice_32b_rx_flex_desc *rx_desc,
			  const struct ice_rx_ring *rx_ring,
			  __le64 full_id);

static inline void
__ice_xdp_handle_meta(struct xdp_buff *xdp, struct xdp_meta_generic_rx *rx_md,
		      const struct xdp_attachment_info *info,
		      const union ice_32b_rx_flex_desc *rx_desc,
		      const struct ice_rx_ring *rx_ring)
{
	rx_md->rx_flags = 0;

	if (xdp->data_end - xdp->data < info->meta_thresh)
		return;

	switch (info->drv_cookie) {
	case ICE_MD_GENERIC:
		__ice_xdp_build_meta(rx_md, rx_desc, rx_ring, info->btf_id_le);

		xdp->data_meta = xdp_meta_generic_ptr(xdp->data);
		memcpy(to_rx_md(xdp->data_meta), rx_md, sizeof(*rx_md));

		/* Just zero Tx flags instead of zeroing the whole part */
		to_gen_md(xdp->data_meta)->tx_flags = 0;
		break;
	default:
		break;
	}
}

static inline void
__ice_xdp_meta_populate_skb(struct sk_buff *skb,
			    struct xdp_meta_generic_rx *rx_md,
			    const void *data,
			    const union ice_32b_rx_flex_desc *rx_desc,
			    const struct ice_rx_ring *rx_ring)
{
	/* __ice_xdp_build_meta() unconditionally sets Rx queue id. If it's
	 * not here, it means that metadata for this frame hasn't been built
	 * yet and we need to do this now. Otherwise, sync onstack metadata
	 * copy and mark meta as nocomp to ignore it on GRO layer.
	 */
	if (rx_md->rx_flags && likely(xdp_meta_has_generic(data))) {
		memcpy(rx_md, to_rx_md(xdp_meta_generic_ptr(data)),
		       sizeof(*rx_md));
		skb_metadata_nocomp_set(skb);
	} else {
		__ice_xdp_build_meta(rx_md, rx_desc, rx_ring, 0);
	}

	__xdp_populate_skb_meta_generic(skb, rx_md);
}

#define ice_xdp_build_meta(md, ...)					\
	__ice_xdp_build_meta(to_rx_md(md), ##__VA_ARGS__)
#define ice_xdp_handle_meta(xdp, md, ...)				\
	__ice_xdp_handle_meta((xdp), to_rx_md(md), ##__VA_ARGS__)
#define ice_xdp_meta_populate_skb(skb, md, ...)				\
	__ice_xdp_meta_populate_skb((skb), to_rx_md(md), ##__VA_ARGS__)

#endif /* !_ICE_TXRX_LIB_H_ */
