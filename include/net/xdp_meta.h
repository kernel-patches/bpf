/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022, Intel Corporation. */

#ifndef __LINUX_NET_XDP_META_H__
#define __LINUX_NET_XDP_META_H__

#include <linux/bitfield.h>
#include <net/xdp.h>
#include <uapi/linux/bpf.h>

/* Drivers not supporting XDP metadata can use this helper, which
 * rejects any room expansion for metadata as a result.
 */
static __always_inline void
xdp_set_data_meta_invalid(struct xdp_buff *xdp)
{
	xdp->data_meta = xdp->data + 1;
}

static __always_inline bool
xdp_data_meta_unsupported(const struct xdp_buff *xdp)
{
	return unlikely(xdp->data_meta > xdp->data);
}

/**
 * xdp_metalen_invalid -- check if the length of a frame's metadata is valid
 * @metalen: the length of the frame's metadata
 *
 * skb_shared_info::meta_len is of 1 byte long, thus it can't be longer than
 * 255, but this always can change. XDP_PACKET_HEADROOM is 256, and this is a
 * UAPI. sizeof(struct xdp_frame) is reserved since xdp_frame is being placed
 * at xdp_buff::data_hard_start whilst being constructed on XDP_REDIRECT.
 * The 32-bit alignment requirement is arbitrary, kept for simplicity and,
 * sometimes, speed.
 */
static inline bool xdp_metalen_invalid(unsigned long metalen)
{
	typeof(metalen) max;

	max = min_t(typeof(max),
		    (typeof_member(struct skb_shared_info, meta_len))~0UL,
		    XDP_PACKET_HEADROOM - sizeof(struct xdp_frame));
	BUILD_BUG_ON(!__builtin_constant_p(max));

	return (metalen & (sizeof(u32) - 1)) || metalen > max;
}

/* We use direct assignments from &xdp_meta_generic to &sk_buff fields,
 * thus they must match.
 */
static_assert((u32)XDP_META_RX_CSUM_NONE == (u32)CHECKSUM_NONE);
static_assert((u32)XDP_META_RX_CSUM_OK == (u32)CHECKSUM_UNNECESSARY);
static_assert((u32)XDP_META_RX_CSUM_COMP == (u32)CHECKSUM_COMPLETE);
static_assert((u32)XDP_META_RX_HASH_NONE == (u32)PKT_HASH_TYPE_NONE);
static_assert((u32)XDP_META_RX_HASH_L2 == (u32)PKT_HASH_TYPE_L2);
static_assert((u32)XDP_META_RX_HASH_L3 == (u32)PKT_HASH_TYPE_L3);
static_assert((u32)XDP_META_RX_HASH_L4 == (u32)PKT_HASH_TYPE_L4);

/* This builds _get(), _set() and _rep() for each bitfield.
 * If you know for sure the field is empty (e.g. you zeroed the struct
 * previously), use faster _set() op to save several cycles, otherwise
 * use _rep() to avoid mixing values.
 */
#define XDP_META_BUILD_FLAGS_ACC(dir, pfx, FLD)				     \
static inline u32							     \
xdp_meta_##dir##_##pfx##_get(const struct xdp_meta_generic *md)		     \
{									     \
	static_assert(__same_type(md->dir##_flags, __le32));		     \
									     \
	return le32_get_bits(md->dir##_flags, XDP_META_##FLD);		     \
}									     \
									     \
static inline void							     \
xdp_meta_##dir##_##pfx##_set(struct xdp_meta_generic *md, u32 val)	     \
{									     \
	md->dir##_flags |= le32_encode_bits(val, XDP_META_##FLD);	     \
}									     \
									     \
static inline void							     \
xdp_meta_##dir##_##pfx##_rep(struct xdp_meta_generic *md, u32 val)	     \
{									     \
	le32p_replace_bits(&md->dir##_flags, val, XDP_META_##FLD);	     \
}									     \

/* This builds _get() and _set() for each structure field -- those are just
 * byteswap operations however.
 * The second static assertion is due to that all of the fields in the
 * structure should be naturally-aligned when ::magic_id starts at
 * `XDP_PACKET_HEADROOM + 8n`, which is the default and recommended case.
 * This check makes no sense for the efficient unaligned access platforms,
 * but helps the rest.
 */
#define XDP_META_BUILD_ACC(dir, pfx, sz)				     \
static inline u##sz							     \
xdp_meta_##dir##_##pfx##_get(const struct xdp_meta_generic *md)		     \
{									     \
	static_assert(__same_type(md->dir##_##pfx, __le##sz));		     \
									     \
	return le##sz##_to_cpu(md->dir##_##pfx);			     \
}									     \
									     \
static inline void							     \
xdp_meta_##dir##_##pfx##_set(struct xdp_meta_generic *md, u##sz val)	     \
{									     \
	static_assert((XDP_PACKET_HEADROOM - sizeof(*md) +		     \
		       sizeof_field(typeof(*md), magic_id) +		     \
		       offsetof(typeof(*md), dir##_##pfx)) %		     \
		      sizeof_field(typeof(*md), dir##_##pfx) == 0);	     \
									     \
	md->dir##_##pfx = cpu_to_le##sz(val);				     \
}

#if 0 /* For grepping/indexers */
u16 xdp_meta_tx_csum_action_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_csum_action_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_tx_csum_action_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_tx_vlan_type_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_vlan_type_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_tx_vlan_type_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_tx_tstamp_action_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_tstamp_action_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_tx_tstamp_action_rep(struct xdp_meta_generic *md, u16 val);
#endif
XDP_META_BUILD_FLAGS_ACC(tx, csum_action, TX_CSUM_ACT);
XDP_META_BUILD_FLAGS_ACC(tx, vlan_type, TX_VLAN_TYPE);
XDP_META_BUILD_FLAGS_ACC(tx, tstamp_action, TX_TSTAMP_ACT);

#if 0
u16 xdp_meta_tx_csum_start_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_csum_start_set(struct xdp_meta_generic *md, u64 val);
u16 xdp_meta_tx_csum_off_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_csum_off_set(struct xdp_meta_generic *md, u64 val);
u16 xdp_meta_tx_vid_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_vid_set(struct xdp_meta_generic *md, u64 val);
u32 xdp_meta_tx_flags_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_flags_set(struct xdp_meta_generic *md, u32 val);
u64 xdp_meta_tx_tstamp_get(const struct xdp_meta_generic *md);
void xdp_meta_tx_tstamp_set(struct xdp_meta_generic *md, u64 val);
#endif
XDP_META_BUILD_ACC(tx, csum_start, 16);
XDP_META_BUILD_ACC(tx, csum_off, 16);
XDP_META_BUILD_ACC(tx, vid, 16);
XDP_META_BUILD_ACC(tx, flags, 32);
XDP_META_BUILD_ACC(tx, tstamp, 64);

#if 0
u16 xdp_meta_rx_csum_status_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_csum_status_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_rx_csum_status_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_rx_csum_level_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_csum_level_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_rx_csum_level_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_rx_hash_type_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_hash_type_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_rx_hash_type_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_rx_vlan_type_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_vlan_type_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_rx_vlan_type_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_rx_tstamp_present_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_tstamp_present_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_rx_tstamp_present_rep(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_rx_qid_present_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_qid_present_set(struct xdp_meta_generic *md, u16 val);
void xdp_meta_rx_qid_present_rep(struct xdp_meta_generic *md, u16 val);
#endif
XDP_META_BUILD_FLAGS_ACC(rx, csum_status, RX_CSUM_STATUS);
XDP_META_BUILD_FLAGS_ACC(rx, csum_level, RX_CSUM_LEVEL);
XDP_META_BUILD_FLAGS_ACC(rx, hash_type, RX_HASH_TYPE);
XDP_META_BUILD_FLAGS_ACC(rx, vlan_type, RX_VLAN_TYPE);
XDP_META_BUILD_FLAGS_ACC(rx, tstamp_present, RX_TSTAMP_PRESENT);
XDP_META_BUILD_FLAGS_ACC(rx, qid_present, RX_QID_PRESENT);

#if 0
u64 xdp_meta_rx_tstamp_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_tstamp_set(struct xdp_meta_generic *md, u64 val);
u32 xdp_meta_rx_hash_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_hash_set(struct xdp_meta_generic *md, u32 val);
u32 xdp_meta_rx_csum_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_csum_set(struct xdp_meta_generic *md, u32 val);
u16 xdp_meta_rx_vid_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_vid_set(struct xdp_meta_generic *md, u16 val);
u16 xdp_meta_rx_qid_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_qid_set(struct xdp_meta_generic *md, u16 val);
u32 xdp_meta_rx_flags_get(const struct xdp_meta_generic *md);
void xdp_meta_rx_flags_set(struct xdp_meta_generic *md, u32 val);
#endif
XDP_META_BUILD_ACC(rx, tstamp, 64);
XDP_META_BUILD_ACC(rx, hash, 32);
XDP_META_BUILD_ACC(rx, csum, 32);
XDP_META_BUILD_ACC(rx, vid, 16);
XDP_META_BUILD_ACC(rx, qid, 16);
XDP_META_BUILD_ACC(rx, flags, 32);

#if 0
u32 xdp_meta_btf_id_get(const struct xdp_meta_generic *md);
void xdp_meta_btf_id_set(struct xdp_meta_generic *md, u32 val);
u32 xdp_meta_type_id_get(const struct xdp_meta_generic *md);
void xdp_meta_type_id_set(struct xdp_meta_generic *md, u32 val);
u64 xdp_meta_full_id_get(const struct xdp_meta_generic *md);
void xdp_meta_full_id_set(struct xdp_meta_generic *md, u64 val);
u16 xdp_meta_magic_id_get(const struct xdp_meta_generic *md);
void xdp_meta_magic_id_set(struct xdp_meta_generic *md, u16 val);
#endif
XDP_META_BUILD_ACC(btf, id, 32);
XDP_META_BUILD_ACC(type, id, 32);
XDP_META_BUILD_ACC(full, id, 64);
XDP_META_BUILD_ACC(magic, id, 16);

/* This allows to jump from xdp_metadata_generic::{tx,rx_full,rx,id} to the
 * parent if needed. For example, declare one of them on stack for convenience
 * and still pass a generic pointer.
 * No out-of-bound checks, a caller must sanitize it on its side.
 */
#define _to_gen_md(ptr, locptr, locmd) ({				      \
	struct xdp_meta_generic *locmd;					      \
	typeof(ptr) locptr = (ptr);					      \
									      \
	if (__same_type(*locptr, typeof(locmd->tx)))			      \
		locmd = (void *)locptr - offsetof(typeof(*locmd), tx);	      \
	else if (__same_type(*locptr, typeof(locmd->rx_full)))		      \
		locmd = (void *)locptr - offsetof(typeof(*locmd), rx_full);   \
	else if (__same_type(*locptr, typeof(locmd->rx)))		      \
		locmd = (void *)locptr - offsetof(typeof(*locmd), rx);	      \
	else if (__same_type(*locptr, typeof(locmd->id)))		      \
		locmd = (void *)locptr - offsetof(typeof(*locmd), id);	      \
	else if (__same_type(*locptr, typeof(locmd)) ||			      \
		 __same_type(*locptr, void))				      \
		locmd = (void *)locptr;					      \
	else								      \
		BUILD_BUG();						      \
									      \
	locmd;								      \
})
#define to_gen_md(ptr)	_to_gen_md((ptr), __UNIQUE_ID(ptr_), __UNIQUE_ID(md_))

/* This allows to pass an xdp_meta_generic pointer instead of an
 * xdp_meta_generic::rx{,_full} pointer for convenience.
 */
#define _to_rx_md(ptr, locptr, locmd) ({				      \
	struct xdp_meta_generic_rx *locmd;				      \
	typeof(ptr) locptr = (ptr);					      \
									      \
	if (__same_type(*locptr, struct xdp_meta_generic_rx))		      \
		locmd = (struct xdp_meta_generic_rx *)locptr;		      \
	else if (__same_type(*locptr, struct xdp_meta_generic) ||	      \
		 __same_type(*locptr, void))				      \
		locmd = &((struct xdp_meta_generic *)locptr)->rx_full;	      \
	else								      \
		BUILD_BUG();						      \
									      \
	locmd;								      \
})
#define to_rx_md(ptr)	_to_rx_md((ptr), __UNIQUE_ID(ptr_), __UNIQUE_ID(md_))

/**
 * xdp_meta_has_generic - get a pointer to the generic metadata before a frame
 * @data: a pointer to the beginning of the frame
 *
 * Note: the function does not perform any access sanity checks, they should
 * be done manually prior to calling it.
 *
 * Returns a pointer to the beginning of the generic metadata.
 */
static inline struct xdp_meta_generic *xdp_meta_generic_ptr(const void *data)
{
	BUILD_BUG_ON(xdp_metalen_invalid(sizeof(struct xdp_meta_generic)));

	return (void *)data - sizeof(struct xdp_meta_generic);
}

/**
 * xdp_meta_has_generic - check whether a frame has a generic meta in front
 * @data: a pointer to the beginning of the frame
 *
 * Returns true if it does, false otherwise.
 */
static inline bool xdp_meta_has_generic(const void *data)
{
	return xdp_meta_generic_ptr(data)->magic_id ==
	       cpu_to_le16(XDP_META_GENERIC_MAGIC);
}

/**
 * xdp_meta_skb_has_generic - check whether an skb has a generic meta
 * @skb: a pointer to the &sk_buff
 *
 * Note: must be called only when skb_mac_header_was_set(skb) == true.
 *
 * Returns true if it does, false otherwise.
 */
static inline bool xdp_meta_skb_has_generic(const struct sk_buff *skb)
{
	return xdp_meta_has_generic(skb_metadata_end(skb));
}

/**
 * xdp_meta_init - initialize a metadata structure
 * @md: pointer to xdp_meta_generic or its ::rx_full or its ::id member
 * @id: full BTF + type ID for the metadata type (can be u* or __le64)
 *
 * Zeroes the passed metadata struct (or part) and initializes its tail, so
 * it becomes ready for further processing. If a driver is responsible for
 * composing metadata, it is important to zero the space it occupies in each
 * Rx buffer as `xdp->data - xdp->data_hard_start` doesn't get initialized
 * by default.
 */
#define _xdp_meta_init(md, id, locmd, locid) ({				      \
	typeof(md) locmd = (md);					      \
	typeof(id) locid = (id);					      \
									      \
	if (offsetof(typeof(*locmd), full_id))				      \
		memset(locmd, 0, offsetof(typeof(*locmd), full_id));	      \
									      \
	locmd->full_id = __same_type(locid, __le64) ? (__force __le64)locid : \
			 cpu_to_le64((__force u64)locid);		      \
	locmd->magic_id = cpu_to_le16(XDP_META_GENERIC_MAGIC);		      \
})
#define xdp_meta_init(md, id)						      \
	_xdp_meta_init((md), (id), __UNIQUE_ID(md_), __UNIQUE_ID(id_))

void ___xdp_build_meta_generic_from_skb(struct xdp_meta_generic_rx *rx_md,
					const struct sk_buff *skb);
void ___xdp_populate_skb_meta_generic(struct sk_buff *skb,
				      const struct xdp_meta_generic_rx *rx_md);

#define _xdp_build_meta_generic_from_skb(md, skb, locmd) ({		      \
	typeof(md) locmd = (md);					      \
									      \
	if (offsetof(typeof(*locmd), rx))				      \
		memset(locmd, 0, offsetof(typeof(*locmd), rx));		      \
									      \
	___xdp_build_meta_generic_from_skb(to_rx_md(locmd), skb);	      \
})
#define __xdp_build_meta_generic_from_skb(md, skb)			      \
	_xdp_build_meta_generic_from_skb((md), (skb), __UNIQUE_ID(md_))

#define __xdp_populate_skb_meta_generic(skb, md)			      \
	___xdp_populate_skb_meta_generic((skb), to_rx_md(md))

/**
 * xdp_build_meta_generic_from_skb - build the generic meta before the skb data
 * @skb: a pointer to the &sk_buff
 *
 * Builds an XDP generic metadata in front of the skb data from its fields.
 * Note: skb->mac_header must be set and valid.
 */
static inline void xdp_build_meta_generic_from_skb(struct sk_buff *skb)
{
	struct xdp_meta_generic *md;
	u32 needed;

	/* skb_headroom() is `skb->data - skb->head`, i.e. it doesn't account
	 * for the pulled headers, e.g. MAC header. Metadata resides in front
	 * of the MAC header, so counting starts from there, not the current
	 * data pointer position.
	 * CoW won't happen in here when coming from Generic XDP path as it
	 * ensures that an skb has at least %XDP_PACKET_HEADROOM beforehand.
	 * It won't be happening also as long as `sizeof(*md) <= NET_SKB_PAD`.
	 */
	needed = (void *)skb->data - skb_metadata_end(skb) + sizeof(*md);
	if (unlikely(skb_cow_head(skb, needed)))
		return;

	md = xdp_meta_generic_ptr(skb_metadata_end(skb));
	__xdp_build_meta_generic_from_skb(md, skb);

	skb_metadata_set(skb, sizeof(*md));
	skb_metadata_nocomp_set(skb);
}

/**
 * xdp_populate_skb_meta_generic - fill an skb from the metadata in front of it
 * @skb: a pointer to the &sk_buff
 *
 * Fills the skb fields from the metadata in front of its MAC header and marks
 * its metadata as "non-comparable".
 * Note: skb->mac_header must be set and valid.
 */
static inline void xdp_populate_skb_meta_generic(struct sk_buff *skb)
{
	const struct xdp_meta_generic *md;

	if (skb_metadata_len(skb) < sizeof(*md))
		return;

	md = xdp_meta_generic_ptr(skb_metadata_end(skb));
	__xdp_populate_skb_meta_generic(skb, md);

	/* We know at this point that skb metadata may contain
	 * unique values, mark it as nocomp to not confuse GRO.
	 */
	skb_metadata_nocomp_set(skb);
}

int xdp_meta_match_id(const char * const *list, u64 id);

#endif /* __LINUX_NET_XDP_META_H__ */
