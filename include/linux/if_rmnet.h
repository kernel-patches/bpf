/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2013-2019, 2021 The Linux Foundation. All rights reserved.
 */

#ifndef _LINUX_IF_RMNET_H_
#define _LINUX_IF_RMNET_H_

#include <linux/types.h>

struct rmnet_map_header {
	u8 flags;			/* MAP_CMD_FLAG, MAP_PAD_LEN_MASK */
	u8 mux_id;
	__be16 pkt_len;			/* Length of packet, including pad */
}  __aligned(1);

/* rmnet_map_header flags field:
 *  PAD_LEN:	  number of pad bytes following packet data
 *  CMD:	  1 = packet contains a MAP command; 0 = packet contains data
 *  NEXT_HEADER: 1 = packet contains V5 CSUM header 0 = no V5 CSUM header
 */
#define MAP_PAD_LEN_MASK		GENMASK(5, 0)
#define MAP_NEXT_HEADER_FLAG		BIT(6)
#define MAP_CMD_FLAG			BIT(7)

struct rmnet_map_dl_csum_trailer {
	u8 reserved1;
	u8 flags;			/* MAP_CSUM_DL_VALID_FLAG */
	__be16 csum_start_offset;
	__be16 csum_length;
	__sum16 csum_value;
} __aligned(1);

/* rmnet_map_dl_csum_trailer flags field:
 *  VALID:	1 = checksum and length valid; 0 = ignore them
 */
#define MAP_CSUM_DL_VALID_FLAG		BIT(0)

struct rmnet_map_ul_csum_header {
	__be16 csum_start_offset;
	__be16 csum_info;		/* MAP_CSUM_UL_* */
} __aligned(1);

/* csum_info field:
 *  OFFSET:	where (offset in bytes) to insert computed checksum
 *  UDP:	1 = UDP checksum (zero checksum means no checksum)
 *  ENABLED:	1 = checksum computation requested
 */
#define MAP_CSUM_UL_OFFSET_MASK		GENMASK(13, 0)
#define MAP_CSUM_UL_UDP_FLAG		BIT(14)
#define MAP_CSUM_UL_ENABLED_FLAG	BIT(15)

/* MAP CSUM headers */
struct rmnet_map_v5_csum_header {
	u8 header_info;
	u8 csum_info;
	__be16 reserved;
} __aligned(1);

/* v5 header_info field
 * NEXT_HEADER: represents whether there is any next header
 * HEADER_TYPE: represents the type of this header
 *
 * csum_info field
 * CSUM_VALID_OR_REQ:
 * 1 = for UL, checksum computation is requested.
 * 1 = for DL, validated the checksum and has found it valid
 */

#define MAPV5_HDRINFO_NXT_HDR_FLAG	BIT(0)
#define MAPV5_HDRINFO_HDR_TYPE_FMASK	GENMASK(7, 1)
#define MAPV5_CSUMINFO_VALID_FLAG	BIT(7)

#define RMNET_MAP_HEADER_TYPE_COALESCING   1
#define RMNET_MAP_HEADER_TYPE_CSUM_OFFLOAD 2

/* MAPv5 coalescing header */
#define RMNET_MAP_V5_MAX_NLOS		6
#define RMNET_MAP_V5_MAX_PACKETS	48

/* One Number-Length Object pair: per-NLO packet count and length. */
struct rmnet_map_v5_nl_pair {
	__be16 pkt_len;
	u8  csum_error_bitmap;
	u8  num_packets;
} __aligned(1);

/* MAPv5 coalescing header: describes up to RMNET_MAP_V5_MAX_NLOS NLOs.
 * The header immediately follows the MAP header in the frame and is
 * included in the MAP pkt_len field.
 */
struct rmnet_map_v5_coal_header {
	u8  header_info;	/* MAPV5_HDRINFO_NXT_HDR_FLAG, MAPV5_HDRINFO_HDR_TYPE_FMASK */
	u8  coal_info;		/* MAPV5_COALINFO_* */
	u8  close_info;		/* MAPV5_CLOSEINFO_* */
	u8  veid_info;		/* MAPV5_VEIDINFO_* */
	struct rmnet_map_v5_nl_pair nl_pairs[RMNET_MAP_V5_MAX_NLOS];
} __aligned(1);

#define MAPV5_COALINFO_NUM_NLOS_FMASK		GENMASK(6, 4)
#define MAPV5_COALINFO_CSUM_VALID_FLAG		BIT(7)
#define MAPV5_CLOSEINFO_CLOSE_TYPE_FMASK	GENMASK(3, 0)
#define MAPV5_CLOSEINFO_CLOSE_VALUE_FMASK	GENMASK(7, 4)
#define MAPV5_VEIDINFO_VEID_FMASK		GENMASK(3, 0)

#endif /* !(_LINUX_IF_RMNET_H_) */
