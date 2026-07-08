/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#ifndef _LAN9645X_STATS_H_
#define _LAN9645X_STATS_H_

#include "lan9645x_main.h"

#define STATS_INDEX(vstats, idx) (&(vstats)->cnts[(vstats)->num_cnts * (idx)])

#define STAT_COUNTERS(lan9645x, type, idx) \
	STATS_INDEX(lan9645x_get_vstats(lan9645x, type), idx)

/* Counter indices into stat layout structs */
#define SCNT_FRER_SID_IN_PKT             0
#define SCNT_ISDX_GREEN_OCT              1
#define SCNT_ISDX_GREEN_PKT              2
#define SCNT_ISDX_YELLOW_OCT             3
#define SCNT_ISDX_YELLOW_PKT             4
#define SCNT_ISDX_RED_OCT                5
#define SCNT_ISDX_RED_PKT                6
#define SCNT_ISDX_DROP_GREEN_OCT         7
#define SCNT_ISDX_DROP_GREEN_PKT         8
#define SCNT_ISDX_DROP_YELLOW_OCT        9
#define SCNT_ISDX_DROP_YELLOW_PKT        10

#define SCNT_SF_MATCHING_FRAMES_COUNT    0
#define SCNT_SF_NOT_PASSING_FRAMES_COUNT 1
#define SCNT_SF_NOT_PASSING_SDU_COUNT    2
#define SCNT_SF_RED_FRAMES_COUNT         3
#define SCNT_SF_STREAM_BLOCK_COUNT       4

#define SCNT_ESDX_GREEN_OCT              0
#define SCNT_ESDX_GREEN_PKT              1
#define SCNT_ESDX_YELLOW_OCT             2
#define SCNT_ESDX_YELLOW_PKT             3

#define SCNT_RX_OCT                      0
#define SCNT_RX_UC                       1
#define SCNT_RX_MC                       2
#define SCNT_RX_BC                       3
#define SCNT_RX_SHORT                    4
#define SCNT_RX_FRAG                     5
#define SCNT_RX_JABBER                   6
#define SCNT_RX_CRC                      7
#define SCNT_RX_SYMBOL_ERR               8
#define SCNT_RX_SZ_64                    9
#define SCNT_RX_SZ_65_127                10
#define SCNT_RX_SZ_128_255               11
#define SCNT_RX_SZ_256_511               12
#define SCNT_RX_SZ_512_1023              13
#define SCNT_RX_SZ_1024_1526             14
#define SCNT_RX_SZ_JUMBO                 15
#define SCNT_RX_PAUSE                    16
#define SCNT_RX_CONTROL                  17
#define SCNT_RX_LONG                     18
#define SCNT_RX_CAT_DROP                 19
#define SCNT_RX_RED_PRIO_0               20
#define SCNT_RX_RED_PRIO_1               21
#define SCNT_RX_RED_PRIO_2               22
#define SCNT_RX_RED_PRIO_3               23
#define SCNT_RX_RED_PRIO_4               24
#define SCNT_RX_RED_PRIO_5               25
#define SCNT_RX_RED_PRIO_6               26
#define SCNT_RX_RED_PRIO_7               27
#define SCNT_RX_YELLOW_PRIO_0            28
#define SCNT_RX_YELLOW_PRIO_1            29
#define SCNT_RX_YELLOW_PRIO_2            30
#define SCNT_RX_YELLOW_PRIO_3            31
#define SCNT_RX_YELLOW_PRIO_4            32
#define SCNT_RX_YELLOW_PRIO_5            33
#define SCNT_RX_YELLOW_PRIO_6            34
#define SCNT_RX_YELLOW_PRIO_7            35
#define SCNT_RX_GREEN_PRIO_0             36
#define SCNT_RX_GREEN_PRIO_1             37
#define SCNT_RX_GREEN_PRIO_2             38
#define SCNT_RX_GREEN_PRIO_3             39
#define SCNT_RX_GREEN_PRIO_4             40
#define SCNT_RX_GREEN_PRIO_5             41
#define SCNT_RX_GREEN_PRIO_6             42
#define SCNT_RX_GREEN_PRIO_7             43
#define SCNT_RX_ASSEMBLY_ERR             44
#define SCNT_RX_SMD_ERR                  45
#define SCNT_RX_ASSEMBLY_OK              46
#define SCNT_RX_MERGE_FRAG               47
#define SCNT_RX_PMAC_OCT                 48
#define SCNT_RX_PMAC_UC                  49
#define SCNT_RX_PMAC_MC                  50
#define SCNT_RX_PMAC_BC                  51
#define SCNT_RX_PMAC_SHORT               52
#define SCNT_RX_PMAC_FRAG                53
#define SCNT_RX_PMAC_JABBER              54
#define SCNT_RX_PMAC_CRC                 55
#define SCNT_RX_PMAC_SYMBOL_ERR          56
#define SCNT_RX_PMAC_SZ_64               57
#define SCNT_RX_PMAC_SZ_65_127           58
#define SCNT_RX_PMAC_SZ_128_255          59
#define SCNT_RX_PMAC_SZ_256_511          60
#define SCNT_RX_PMAC_SZ_512_1023         61
#define SCNT_RX_PMAC_SZ_1024_1526        62
#define SCNT_RX_PMAC_SZ_JUMBO            63
#define SCNT_RX_PMAC_PAUSE               64
#define SCNT_RX_PMAC_CONTROL             65
#define SCNT_RX_PMAC_LONG                66
#define SCNT_TX_OCT                      67
#define SCNT_TX_UC                       68
#define SCNT_TX_MC                       69
#define SCNT_TX_BC                       70
#define SCNT_TX_COL                      71
#define SCNT_TX_DROP                     72
#define SCNT_TX_PAUSE                    73
#define SCNT_TX_SZ_64                    74
#define SCNT_TX_SZ_65_127                75
#define SCNT_TX_SZ_128_255               76
#define SCNT_TX_SZ_256_511               77
#define SCNT_TX_SZ_512_1023              78
#define SCNT_TX_SZ_1024_1526             79
#define SCNT_TX_SZ_JUMBO                 80
#define SCNT_TX_YELLOW_PRIO_0            81
#define SCNT_TX_YELLOW_PRIO_1            82
#define SCNT_TX_YELLOW_PRIO_2            83
#define SCNT_TX_YELLOW_PRIO_3            84
#define SCNT_TX_YELLOW_PRIO_4            85
#define SCNT_TX_YELLOW_PRIO_5            86
#define SCNT_TX_YELLOW_PRIO_6            87
#define SCNT_TX_YELLOW_PRIO_7            88
#define SCNT_TX_GREEN_PRIO_0             89
#define SCNT_TX_GREEN_PRIO_1             90
#define SCNT_TX_GREEN_PRIO_2             91
#define SCNT_TX_GREEN_PRIO_3             92
#define SCNT_TX_GREEN_PRIO_4             93
#define SCNT_TX_GREEN_PRIO_5             94
#define SCNT_TX_GREEN_PRIO_6             95
#define SCNT_TX_GREEN_PRIO_7             96
#define SCNT_TX_AGED                     97
#define SCNT_TX_LLCT                     98
#define SCNT_TX_CT                       99
#define SCNT_TX_BUFDROP                  100
#define SCNT_TX_MM_HOLD                  101
#define SCNT_TX_MERGE_FRAG               102
#define SCNT_TX_PMAC_OCT                 103
#define SCNT_TX_PMAC_UC                  104
#define SCNT_TX_PMAC_MC                  105
#define SCNT_TX_PMAC_BC                  106
#define SCNT_TX_PMAC_PAUSE               107
#define SCNT_TX_PMAC_SZ_64               108
#define SCNT_TX_PMAC_SZ_65_127           109
#define SCNT_TX_PMAC_SZ_128_255          110
#define SCNT_TX_PMAC_SZ_256_511          111
#define SCNT_TX_PMAC_SZ_512_1023         112
#define SCNT_TX_PMAC_SZ_1024_1526        113
#define SCNT_TX_PMAC_SZ_JUMBO            114
#define SCNT_DR_LOCAL                    115
#define SCNT_DR_TAIL                     116
#define SCNT_DR_YELLOW_PRIO_0            117
#define SCNT_DR_YELLOW_PRIO_1            118
#define SCNT_DR_YELLOW_PRIO_2            119
#define SCNT_DR_YELLOW_PRIO_3            120
#define SCNT_DR_YELLOW_PRIO_4            121
#define SCNT_DR_YELLOW_PRIO_5            122
#define SCNT_DR_YELLOW_PRIO_6            123
#define SCNT_DR_YELLOW_PRIO_7            124
#define SCNT_DR_GREEN_PRIO_0             125
#define SCNT_DR_GREEN_PRIO_1             126
#define SCNT_DR_GREEN_PRIO_2             127
#define SCNT_DR_GREEN_PRIO_3             128
#define SCNT_DR_GREEN_PRIO_4             129
#define SCNT_DR_GREEN_PRIO_5             130
#define SCNT_DR_GREEN_PRIO_6             131
#define SCNT_DR_GREEN_PRIO_7             132

enum lan9645x_view_stat_type {
	LAN9645X_STAT_PORTS = 0,
	LAN9645X_STAT_ISDX,
	LAN9645X_STAT_ESDX,
	LAN9645X_STAT_SFID,

	LAN9645X_STAT_NUM,
};

struct lan9645x_stat_region {
	u32 base_offset;
	u32 cnt;
	u32 cnts_base_idx;
};

/* Counters are organized by indices/views such as
 *
 * - physical ports
 * - isdx
 * - esdx
 * - frer
 * - sfid
 *
 * Each view contains regions, which is a linear address range of related
 * stats. I.e. the ports index has RX, TX and Drop regions.
 *
 *
 * and you have a given counter replicated per index.
 */
struct lan9645x_view_stats {
	/* HW register offsets indexed by SCNT_*, used for bulk reading */
	const u32 *layout;
	/* Region description for this view, used for bulk reading */
	struct lan9645x_stat_region *regions;
	struct lan9645x_stats *stats;
	char name[16];
	/* 64bit software counters with the same addr layout hw */
	u64 *cnts;
	/* Buffer for bulk reading counter regions from hw */
	u32 *buf;
	/* Number of counters per index in view */
	u32 num_cnts;
	/* Number of indexes in view */
	u32 num_indexes;
	/* Number of counter regions with counters at sequential addresses */
	size_t num_regions;
	enum lan9645x_view_stat_type type;
};

struct lan9645x_stats {
	struct lan9645x *lan9645x;
	struct mutex hw_lock; /* lock r/w to stat registers and u32 buf */
	spinlock_t sw_lock; /* lock access to u64 software counters */
	struct delayed_work work;
	struct workqueue_struct *queue;

	struct lan9645x_view_stats view[LAN9645X_STAT_NUM];
};

static inline struct lan9645x_view_stats *
lan9645x_get_vstats(struct lan9645x *lan9645x,
		    enum lan9645x_view_stat_type type)
{
	if (WARN_ON(!(type < LAN9645X_STAT_NUM)))
		return NULL;

	return &lan9645x->stats->view[type];
}

/* Add a possibly wrapping 32 bit value to a 64 bit counter */
static inline void lan9645x_stats_add_cnt(u64 *cnt, u32 val)
{
	if (val < (*cnt & U32_MAX))
		*cnt += (u64)1 << 32; /* value has wrapped */

	*cnt = (*cnt & ~(u64)U32_MAX) + val;
}

int lan9645x_stats_alloc(struct lan9645x *lan9645x);
void lan9645x_stats_free(struct lan9645x *lan9645x);
void lan9645x_stats_init(struct lan9645x *lan9645x);
void lan9645x_stats_deinit(struct lan9645x *lan9645x);
void lan9645x_stats_get_strings(struct lan9645x *lan9645x, int port,
				u32 stringset, u8 *data);
int lan9645x_stats_get_sset_count(struct lan9645x *lan9645x, int port,
				  int sset);
void lan9645x_stats_get_ethtool_stats(struct lan9645x *lan9645x, int port,
				      uint64_t *data);
void lan9645x_stats_get_eth_mac_stats(struct lan9645x *lan9645x, int port,
				      struct ethtool_eth_mac_stats *mac_stats);
void
lan9645x_stats_get_rmon_stats(struct lan9645x *lan9645x, int port,
			      struct ethtool_rmon_stats *rmon_stats,
			      const struct ethtool_rmon_hist_range **ranges);
void lan9645x_stats_get_stats64(struct lan9645x *lan9645x, int port,
				struct rtnl_link_stats64 *s);
void lan9645x_stats_get_mm_stats(struct lan9645x *lan9645x, int port,
				 struct ethtool_mm_stats *stats);
void lan9645x_stats_get_pause_stats(struct lan9645x *lan9645x, int port,
				    struct ethtool_pause_stats *ps);
void
lan9645x_stats_get_eth_ctrl_stats(struct lan9645x *lan9645x, int port,
				  struct ethtool_eth_ctrl_stats *ctrl_stats);
void lan9645x_stats_get_eth_phy_stats(struct lan9645x *lan9645x, int port,
				      struct ethtool_eth_phy_stats *phy_stats);

#endif
