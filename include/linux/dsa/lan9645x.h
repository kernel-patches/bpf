/* SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2026 Microchip Technology Inc.
 */

#ifndef _NET_DSA_TAG_LAN9645X_H_
#define _NET_DSA_TAG_LAN9645X_H_

#include <net/dsa.h>

/* LAN9645x supports 3 different formats on an NPI port, long prefix, short
 * prefix and no prefix. The format can be configured asymmetrically on RX and
 * TX. We use long prefix on extraction (RX), and no prefix on injection.
 * The long prefix on extraction helps get through the conduit port on host
 * side, since it will see a broadcast MAC.
 *
 * The internal frame header (IFH) is 28 bytes, and the fields are documented
 * below.
 *
 * Long prefix, 16 bytes + IFH:
 * - DMAC    = 0xFFFFFFFFFFFF on extraction.
 * - SMAC    = 0xFEFFFFFFFFFF on extraction.
 * - ETYPE   = 0x8880
 * - payload = 0x0011
 * - IFH
 *
 * Short prefix, 4 bytes + IFH:
 * - 0x8880
 * - 0x0011
 * - IFH
 *
 * No prefix:
 * - IFH
 *
 */
#define LAN9645X_IFH_TAG_TYPE_C	0
#define LAN9645X_IFH_TAG_TYPE_S	1
#define LAN9645X_IFH_LEN_U32		7
#define LAN9645X_IFH_LEN		(LAN9645X_IFH_LEN_U32 * sizeof(u32))
#define LAN9645X_IFH_BITS		(LAN9645X_IFH_LEN * BITS_PER_BYTE)
#define LAN9645X_SHORT_PREFIX_LEN	4
#define LAN9645X_LONG_PREFIX_LEN	16
#define LAN9645X_TOTAL_TAG_LEN (LAN9645X_LONG_PREFIX_LEN + LAN9645X_IFH_LEN)

#define IFH_INJ_TIMESTAMP		192
#define IFH_BYPASS			191
#define IFH_MASQ			190
#define IFH_TIMESTAMP			186
#define IFH_TIMESTAMP_NS		194
#define IFH_TIMESTAMP_SUBNS		186
#define IFH_MASQ_PORT			186
#define IFH_RCT_INJ			185
#define IFH_LEN				171
#define IFH_WRDMODE			169
#define IFH_RTAGD			167
#define IFH_CUTTHRU			166
#define IFH_REW_CMD			156
#define IFH_REW_OAM			155
#define IFH_PDU_TYPE			151
#define IFH_FCS_UPD			150
#define IFH_DP				149
#define IFH_RTE_INB_UPDATE		148
#define IFH_POP_CNT			146
#define IFH_ETYPE_OFS			144
#define IFH_SRCPORT			140
#define IFH_SEQ_NUM			120
#define IFH_TAG_TYPE			119
#define IFH_TCI				103
#define IFH_DSCP			97
#define IFH_QOS_CLASS			94
#define IFH_CPUQ			86
#define IFH_LEARN_FLAGS			84
#define IFH_SFLOW_ID			80
#define IFH_ACL_HIT			79
#define IFH_ACL_IDX			73
#define IFH_ISDX			65
#define IFH_DSTS			55
#define IFH_FLOOD			53
#define IFH_SEQ_OP			51
#define IFH_IPV				48
#define IFH_AFI				47
#define IFH_RTP_ID			37
#define IFH_RTP_SUBID			36
#define IFH_PN_DATA_STATUS		28
#define IFH_PN_TRANSF_STATUS_ZERO	27
#define IFH_PN_CC			11
#define IFH_DUPL_DISC_ENA		10
#define IFH_RCT_AVAIL			9

#define IFH_INJ_TIMESTAMP_SZ		32
#define IFH_BYPASS_SZ			1
#define IFH_MASQ_SZ			1
#define IFH_TIMESTAMP_SZ		38
#define IFH_TIMESTAMP_NS_SZ		30
#define IFH_TIMESTAMP_SUBNS_SZ		8
#define IFH_MASQ_PORT_SZ		4
#define IFH_RCT_INJ_SZ			1
#define IFH_LEN_SZ			14
#define IFH_WRDMODE_SZ			2
#define IFH_RTAGD_SZ			2
#define IFH_CUTTHRU_SZ			1
#define IFH_REW_CMD_SZ			10
#define IFH_REW_OAM_SZ			1
#define IFH_PDU_TYPE_SZ			4
#define IFH_FCS_UPD_SZ			1
#define IFH_DP_SZ			1
#define IFH_RTE_INB_UPDATE_SZ		1
#define IFH_POP_CNT_SZ			2
#define IFH_ETYPE_OFS_SZ		2
#define IFH_SRCPORT_SZ			4
#define IFH_SEQ_NUM_SZ			16
#define IFH_TAG_TYPE_SZ			1
#define IFH_TCI_SZ			16
#define IFH_DSCP_SZ			6
#define IFH_QOS_CLASS_SZ		3
#define IFH_CPUQ_SZ			8
#define IFH_LEARN_FLAGS_SZ		2
#define IFH_SFLOW_ID_SZ			4
#define IFH_ACL_HIT_SZ			1
#define IFH_ACL_IDX_SZ			6
#define IFH_ISDX_SZ			8
#define IFH_DSTS_SZ			10
#define IFH_FLOOD_SZ			2
#define IFH_SEQ_OP_SZ			2
#define IFH_IPV_SZ			3
#define IFH_AFI_SZ			1
#define IFH_RTP_ID_SZ			10
#define IFH_RTP_SUBID_SZ		1
#define IFH_PN_DATA_STATUS_SZ		8
#define IFH_PN_TRANSF_STATUS_ZERO_SZ	1
#define IFH_PN_CC_SZ			16
#define IFH_DUPL_DISC_ENA_SZ		1
#define IFH_RCT_AVAIL_SZ		1

/* Chip has 8 cpu queues. The cpu queues used by a frame is passed as a mask in
 * the IFH on extraction. We use this to avoid classifying BPDU, IGMP and MLD
 * frames in the tag driver.
 */
enum {
	LAN9645X_CPUQ_DEF = 0,
	LAN9645X_CPUQ_TRAP = 1,
	LAN9645X_CPUQ_COPY = 2,
};

#endif /* _NET_DSA_TAG_LAN9645X_H_ */
