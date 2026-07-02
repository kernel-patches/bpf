// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "lan9645x_main.h"
#include "lan9645x_stats.h"

#define LAN9645X_STATS_CHECK_DELAY	(3 * HZ)

static const u32 lan9645x_port_stats_layout[] = {
	[SCNT_RX_OCT]              = 0x0,
	[SCNT_RX_UC]               = 0x1,
	[SCNT_RX_MC]               = 0x2,
	[SCNT_RX_BC]               = 0x3,
	[SCNT_RX_SHORT]            = 0x4,
	[SCNT_RX_FRAG]             = 0x5,
	[SCNT_RX_JABBER]           = 0x6,
	[SCNT_RX_CRC]              = 0x7,
	[SCNT_RX_SYMBOL_ERR]       = 0x8,
	[SCNT_RX_SZ_64]            = 0x9,
	[SCNT_RX_SZ_65_127]        = 0xa,
	[SCNT_RX_SZ_128_255]       = 0xb,
	[SCNT_RX_SZ_256_511]       = 0xc,
	[SCNT_RX_SZ_512_1023]      = 0xd,
	[SCNT_RX_SZ_1024_1526]     = 0xe,
	[SCNT_RX_SZ_JUMBO]         = 0xf,
	[SCNT_RX_PAUSE]            = 0x10,
	[SCNT_RX_CONTROL]          = 0x11,
	[SCNT_RX_LONG]             = 0x12,
	[SCNT_RX_CAT_DROP]         = 0x13,
	[SCNT_RX_RED_PRIO_0]       = 0x14,
	[SCNT_RX_RED_PRIO_1]       = 0x15,
	[SCNT_RX_RED_PRIO_2]       = 0x16,
	[SCNT_RX_RED_PRIO_3]       = 0x17,
	[SCNT_RX_RED_PRIO_4]       = 0x18,
	[SCNT_RX_RED_PRIO_5]       = 0x19,
	[SCNT_RX_RED_PRIO_6]       = 0x1a,
	[SCNT_RX_RED_PRIO_7]       = 0x1b,
	[SCNT_RX_YELLOW_PRIO_0]    = 0x1c,
	[SCNT_RX_YELLOW_PRIO_1]    = 0x1d,
	[SCNT_RX_YELLOW_PRIO_2]    = 0x1e,
	[SCNT_RX_YELLOW_PRIO_3]    = 0x1f,
	[SCNT_RX_YELLOW_PRIO_4]    = 0x20,
	[SCNT_RX_YELLOW_PRIO_5]    = 0x21,
	[SCNT_RX_YELLOW_PRIO_6]    = 0x22,
	[SCNT_RX_YELLOW_PRIO_7]    = 0x23,
	[SCNT_RX_GREEN_PRIO_0]     = 0x24,
	[SCNT_RX_GREEN_PRIO_1]     = 0x25,
	[SCNT_RX_GREEN_PRIO_2]     = 0x26,
	[SCNT_RX_GREEN_PRIO_3]     = 0x27,
	[SCNT_RX_GREEN_PRIO_4]     = 0x28,
	[SCNT_RX_GREEN_PRIO_5]     = 0x29,
	[SCNT_RX_GREEN_PRIO_6]     = 0x2a,
	[SCNT_RX_GREEN_PRIO_7]     = 0x2b,
	[SCNT_RX_ASSEMBLY_ERR]     = 0x2c,
	[SCNT_RX_SMD_ERR]          = 0x2d,
	[SCNT_RX_ASSEMBLY_OK]      = 0x2e,
	[SCNT_RX_MERGE_FRAG]       = 0x2f,
	[SCNT_RX_PMAC_OCT]         = 0x30,
	[SCNT_RX_PMAC_UC]          = 0x31,
	[SCNT_RX_PMAC_MC]          = 0x32,
	[SCNT_RX_PMAC_BC]          = 0x33,
	[SCNT_RX_PMAC_SHORT]       = 0x34,
	[SCNT_RX_PMAC_FRAG]        = 0x35,
	[SCNT_RX_PMAC_JABBER]      = 0x36,
	[SCNT_RX_PMAC_CRC]         = 0x37,
	[SCNT_RX_PMAC_SYMBOL_ERR]  = 0x38,
	[SCNT_RX_PMAC_SZ_64]       = 0x39,
	[SCNT_RX_PMAC_SZ_65_127]   = 0x3a,
	[SCNT_RX_PMAC_SZ_128_255]  = 0x3b,
	[SCNT_RX_PMAC_SZ_256_511]  = 0x3c,
	[SCNT_RX_PMAC_SZ_512_1023] = 0x3d,
	[SCNT_RX_PMAC_SZ_1024_1526] = 0x3e,
	[SCNT_RX_PMAC_SZ_JUMBO]    = 0x3f,
	[SCNT_RX_PMAC_PAUSE]       = 0x40,
	[SCNT_RX_PMAC_CONTROL]     = 0x41,
	[SCNT_RX_PMAC_LONG]        = 0x42,
	[SCNT_TX_OCT]              = 0x80,
	[SCNT_TX_UC]               = 0x81,
	[SCNT_TX_MC]               = 0x82,
	[SCNT_TX_BC]               = 0x83,
	[SCNT_TX_COL]              = 0x84,
	[SCNT_TX_DROP]             = 0x85,
	[SCNT_TX_PAUSE]            = 0x86,
	[SCNT_TX_SZ_64]            = 0x87,
	[SCNT_TX_SZ_65_127]        = 0x88,
	[SCNT_TX_SZ_128_255]       = 0x89,
	[SCNT_TX_SZ_256_511]       = 0x8a,
	[SCNT_TX_SZ_512_1023]      = 0x8b,
	[SCNT_TX_SZ_1024_1526]     = 0x8c,
	[SCNT_TX_SZ_JUMBO]         = 0x8d,
	[SCNT_TX_YELLOW_PRIO_0]    = 0x8e,
	[SCNT_TX_YELLOW_PRIO_1]    = 0x8f,
	[SCNT_TX_YELLOW_PRIO_2]    = 0x90,
	[SCNT_TX_YELLOW_PRIO_3]    = 0x91,
	[SCNT_TX_YELLOW_PRIO_4]    = 0x92,
	[SCNT_TX_YELLOW_PRIO_5]    = 0x93,
	[SCNT_TX_YELLOW_PRIO_6]    = 0x94,
	[SCNT_TX_YELLOW_PRIO_7]    = 0x95,
	[SCNT_TX_GREEN_PRIO_0]     = 0x96,
	[SCNT_TX_GREEN_PRIO_1]     = 0x97,
	[SCNT_TX_GREEN_PRIO_2]     = 0x98,
	[SCNT_TX_GREEN_PRIO_3]     = 0x99,
	[SCNT_TX_GREEN_PRIO_4]     = 0x9a,
	[SCNT_TX_GREEN_PRIO_5]     = 0x9b,
	[SCNT_TX_GREEN_PRIO_6]     = 0x9c,
	[SCNT_TX_GREEN_PRIO_7]     = 0x9d,
	[SCNT_TX_AGED]             = 0x9e,
	[SCNT_TX_LLCT]             = 0x9f,
	[SCNT_TX_CT]               = 0xa0,
	[SCNT_TX_BUFDROP]          = 0xa1,
	[SCNT_TX_MM_HOLD]          = 0xa2,
	[SCNT_TX_MERGE_FRAG]       = 0xa3,
	[SCNT_TX_PMAC_OCT]         = 0xa4,
	[SCNT_TX_PMAC_UC]          = 0xa5,
	[SCNT_TX_PMAC_MC]          = 0xa6,
	[SCNT_TX_PMAC_BC]          = 0xa7,
	[SCNT_TX_PMAC_PAUSE]       = 0xa8,
	[SCNT_TX_PMAC_SZ_64]       = 0xa9,
	[SCNT_TX_PMAC_SZ_65_127]   = 0xaa,
	[SCNT_TX_PMAC_SZ_128_255]  = 0xab,
	[SCNT_TX_PMAC_SZ_256_511]  = 0xac,
	[SCNT_TX_PMAC_SZ_512_1023] = 0xad,
	[SCNT_TX_PMAC_SZ_1024_1526] = 0xae,
	[SCNT_TX_PMAC_SZ_JUMBO]    = 0xaf,
	[SCNT_DR_LOCAL]            = 0x100,
	[SCNT_DR_TAIL]             = 0x101,
	[SCNT_DR_YELLOW_PRIO_0]    = 0x102,
	[SCNT_DR_YELLOW_PRIO_1]    = 0x103,
	[SCNT_DR_YELLOW_PRIO_2]    = 0x104,
	[SCNT_DR_YELLOW_PRIO_3]    = 0x105,
	[SCNT_DR_YELLOW_PRIO_4]    = 0x106,
	[SCNT_DR_YELLOW_PRIO_5]    = 0x107,
	[SCNT_DR_YELLOW_PRIO_6]    = 0x108,
	[SCNT_DR_YELLOW_PRIO_7]    = 0x109,
	[SCNT_DR_GREEN_PRIO_0]     = 0x10a,
	[SCNT_DR_GREEN_PRIO_1]     = 0x10b,
	[SCNT_DR_GREEN_PRIO_2]     = 0x10c,
	[SCNT_DR_GREEN_PRIO_3]     = 0x10d,
	[SCNT_DR_GREEN_PRIO_4]     = 0x10e,
	[SCNT_DR_GREEN_PRIO_5]     = 0x10f,
	[SCNT_DR_GREEN_PRIO_6]     = 0x110,
	[SCNT_DR_GREEN_PRIO_7]     = 0x111,
};

struct lan9645x_ethtool_stat {
	char name[ETH_GSTRING_LEN];
	u16 idx;
};

static const struct lan9645x_ethtool_stat lan9645x_port_ethtool_stats[] = {
	{ "rx_cat_drop",        SCNT_RX_CAT_DROP },
	{ "rx_red_prio_0",      SCNT_RX_RED_PRIO_0 },
	{ "rx_red_prio_1",      SCNT_RX_RED_PRIO_1 },
	{ "rx_red_prio_2",      SCNT_RX_RED_PRIO_2 },
	{ "rx_red_prio_3",      SCNT_RX_RED_PRIO_3 },
	{ "rx_red_prio_4",      SCNT_RX_RED_PRIO_4 },
	{ "rx_red_prio_5",      SCNT_RX_RED_PRIO_5 },
	{ "rx_red_prio_6",      SCNT_RX_RED_PRIO_6 },
	{ "rx_red_prio_7",      SCNT_RX_RED_PRIO_7 },
	{ "rx_yellow_prio_0",   SCNT_RX_YELLOW_PRIO_0 },
	{ "rx_yellow_prio_1",   SCNT_RX_YELLOW_PRIO_1 },
	{ "rx_yellow_prio_2",   SCNT_RX_YELLOW_PRIO_2 },
	{ "rx_yellow_prio_3",   SCNT_RX_YELLOW_PRIO_3 },
	{ "rx_yellow_prio_4",   SCNT_RX_YELLOW_PRIO_4 },
	{ "rx_yellow_prio_5",   SCNT_RX_YELLOW_PRIO_5 },
	{ "rx_yellow_prio_6",   SCNT_RX_YELLOW_PRIO_6 },
	{ "rx_yellow_prio_7",   SCNT_RX_YELLOW_PRIO_7 },
	{ "rx_green_prio_0",    SCNT_RX_GREEN_PRIO_0 },
	{ "rx_green_prio_1",    SCNT_RX_GREEN_PRIO_1 },
	{ "rx_green_prio_2",    SCNT_RX_GREEN_PRIO_2 },
	{ "rx_green_prio_3",    SCNT_RX_GREEN_PRIO_3 },
	{ "rx_green_prio_4",    SCNT_RX_GREEN_PRIO_4 },
	{ "rx_green_prio_5",    SCNT_RX_GREEN_PRIO_5 },
	{ "rx_green_prio_6",    SCNT_RX_GREEN_PRIO_6 },
	{ "rx_green_prio_7",    SCNT_RX_GREEN_PRIO_7 },
	{ "tx_drop",            SCNT_TX_DROP },
	{ "tx_yellow_prio_0",   SCNT_TX_YELLOW_PRIO_0 },
	{ "tx_yellow_prio_1",   SCNT_TX_YELLOW_PRIO_1 },
	{ "tx_yellow_prio_2",   SCNT_TX_YELLOW_PRIO_2 },
	{ "tx_yellow_prio_3",   SCNT_TX_YELLOW_PRIO_3 },
	{ "tx_yellow_prio_4",   SCNT_TX_YELLOW_PRIO_4 },
	{ "tx_yellow_prio_5",   SCNT_TX_YELLOW_PRIO_5 },
	{ "tx_yellow_prio_6",   SCNT_TX_YELLOW_PRIO_6 },
	{ "tx_yellow_prio_7",   SCNT_TX_YELLOW_PRIO_7 },
	{ "tx_green_prio_0",    SCNT_TX_GREEN_PRIO_0 },
	{ "tx_green_prio_1",    SCNT_TX_GREEN_PRIO_1 },
	{ "tx_green_prio_2",    SCNT_TX_GREEN_PRIO_2 },
	{ "tx_green_prio_3",    SCNT_TX_GREEN_PRIO_3 },
	{ "tx_green_prio_4",    SCNT_TX_GREEN_PRIO_4 },
	{ "tx_green_prio_5",    SCNT_TX_GREEN_PRIO_5 },
	{ "tx_green_prio_6",    SCNT_TX_GREEN_PRIO_6 },
	{ "tx_green_prio_7",    SCNT_TX_GREEN_PRIO_7 },
	{ "tx_aged",            SCNT_TX_AGED },
	{ "tx_bufdrop",         SCNT_TX_BUFDROP },
	{ "dr_local",           SCNT_DR_LOCAL },
	{ "dr_tail",            SCNT_DR_TAIL },
	{ "dr_yellow_prio_0",   SCNT_DR_YELLOW_PRIO_0 },
	{ "dr_yellow_prio_1",   SCNT_DR_YELLOW_PRIO_1 },
	{ "dr_yellow_prio_2",   SCNT_DR_YELLOW_PRIO_2 },
	{ "dr_yellow_prio_3",   SCNT_DR_YELLOW_PRIO_3 },
	{ "dr_yellow_prio_4",   SCNT_DR_YELLOW_PRIO_4 },
	{ "dr_yellow_prio_5",   SCNT_DR_YELLOW_PRIO_5 },
	{ "dr_yellow_prio_6",   SCNT_DR_YELLOW_PRIO_6 },
	{ "dr_yellow_prio_7",   SCNT_DR_YELLOW_PRIO_7 },
	{ "dr_green_prio_0",    SCNT_DR_GREEN_PRIO_0 },
	{ "dr_green_prio_1",    SCNT_DR_GREEN_PRIO_1 },
	{ "dr_green_prio_2",    SCNT_DR_GREEN_PRIO_2 },
	{ "dr_green_prio_3",    SCNT_DR_GREEN_PRIO_3 },
	{ "dr_green_prio_4",    SCNT_DR_GREEN_PRIO_4 },
	{ "dr_green_prio_5",    SCNT_DR_GREEN_PRIO_5 },
	{ "dr_green_prio_6",    SCNT_DR_GREEN_PRIO_6 },
	{ "dr_green_prio_7",    SCNT_DR_GREEN_PRIO_7 },
};

static const struct lan9645x_view_stats lan9645x_view_stat_cfgs[] = {
	[LAN9645X_STAT_PORTS] = {
		.name = "ports",
		.type = LAN9645X_STAT_PORTS,
		.layout = lan9645x_port_stats_layout,
		.num_cnts = ARRAY_SIZE(lan9645x_port_stats_layout),
		.num_indexes = NUM_PHYS_PORTS,
	},
};

static int __lan9645x_stats_view_idx_hw_read(struct lan9645x *lan9645x,
					     enum lan9645x_view_stat_type vtype,
					     int idx)
{
	struct lan9645x_stat_region region;
	struct lan9645x_view_stats *vstats;
	u32 *region_buf;
	int err;

	lockdep_assert_held(&lan9645x->stats->hw_lock);

	vstats = lan9645x_get_vstats(lan9645x, vtype);
	if (!vstats || idx < 0 || idx >= vstats->num_indexes)
		return -EINVAL;

	lan_wr(SYS_STAT_CFG_STAT_VIEW_SET(idx), lan9645x, SYS_STAT_CFG);

	region_buf = &vstats->buf[vstats->num_cnts * idx];

	/* Each region for this index contains counters which are at sequential
	 * addresses, so we can use bulk reads to ease lock pressure a bit.
	 */
	for (int r = 0; r < vstats->num_regions; r++) {
		region = vstats->regions[r];
		err = lan_bulk_rd(&region_buf[region.cnts_base_idx], region.cnt,
				  lan9645x, SYS_CNT(region.base_offset));
		if (err) {
			dev_err(lan9645x->dev,
				"stats bulk read err vtype=%d idx=%d err=%d\n",
				vtype, idx, err);
			return err;
		}
	}

	return 0;
}

static void
__lan9645x_stats_view_idx_transfer(struct lan9645x *lan9645x,
				   enum lan9645x_view_stat_type vtype, int idx)
{
	struct lan9645x_view_stats *vstats;
	u64 *idx_counters;
	u32 *region_buf;
	int cntr;

	lockdep_assert_held(&lan9645x->stats->sw_lock);

	vstats = lan9645x_get_vstats(lan9645x, vtype);
	if (!vstats || idx < 0 || idx >= vstats->num_indexes)
		return;

	idx_counters = STATS_INDEX(vstats, idx);
	region_buf = &vstats->buf[vstats->num_cnts * idx];

	for (cntr = 0; cntr < vstats->num_cnts; cntr++)
		lan9645x_stats_add_cnt(&idx_counters[cntr], region_buf[cntr]);
}

static void __lan9645x_stats_view_idx_update(struct lan9645x *lan9645x,
					     enum lan9645x_view_stat_type vtype,
					     int idx)
{
	struct lan9645x_stats *s = lan9645x->stats;

	lockdep_assert_held(&s->hw_lock);

	if (!__lan9645x_stats_view_idx_hw_read(lan9645x, vtype, idx)) {
		spin_lock(&s->sw_lock);
		__lan9645x_stats_view_idx_transfer(lan9645x, vtype, idx);
		spin_unlock(&s->sw_lock);
	}
}

static u64 *lan9645x_stats_view_idx_update(struct lan9645x *lan9645x,
					   enum lan9645x_view_stat_type vtype,
					   int idx)
{
	struct lan9645x_stats *s = lan9645x->stats;

	mutex_lock(&s->hw_lock);
	__lan9645x_stats_view_idx_update(lan9645x, vtype, idx);
	mutex_unlock(&s->hw_lock);

	return STAT_COUNTERS(lan9645x, vtype, idx);
}

static void lan9645x_stats_view_update(struct lan9645x *lan9645x,
				       enum lan9645x_view_stat_type vtype)
{
	struct lan9645x_stats *s = lan9645x->stats;
	struct lan9645x_view_stats *vstats;
	int idx;

	vstats = lan9645x_get_vstats(lan9645x, vtype);
	if (!vstats)
		return;

	switch (vtype) {
	case LAN9645X_STAT_PORTS:
		mutex_lock(&s->hw_lock);
		for (idx = 0; idx < vstats->num_indexes; idx++) {
			if (dsa_is_unused_port(lan9645x->ds, idx))
				continue;
			__lan9645x_stats_view_idx_update(lan9645x, vtype, idx);
		}
		mutex_unlock(&s->hw_lock);
		return;
	default:
		return;
	}
}

static void lan9645x_stats_update(struct lan9645x *lan9645x)
{
	for (int vtype = 0; vtype < LAN9645X_STAT_NUM; vtype++)
		lan9645x_stats_view_update(lan9645x, vtype);
}

void lan9645x_stats_get_strings(struct lan9645x *lan9645x, int port,
				u32 stringset, u8 *data)
{
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < ARRAY_SIZE(lan9645x_port_ethtool_stats); i++)
		memcpy(data + i * ETH_GSTRING_LEN,
		       lan9645x_port_ethtool_stats[i].name, ETH_GSTRING_LEN);
}

int lan9645x_stats_get_sset_count(struct lan9645x *lan9645x, int port, int sset)
{
	if (sset != ETH_SS_STATS)
		return -EOPNOTSUPP;

	return ARRAY_SIZE(lan9645x_port_ethtool_stats);
}

void lan9645x_stats_get_ethtool_stats(struct lan9645x *lan9645x, int port,
				      u64 *data)
{
	struct lan9645x_stats *stats = lan9645x->stats;
	u64 *c;
	int i;

	c = lan9645x_stats_view_idx_update(lan9645x, LAN9645X_STAT_PORTS, port);

	spin_lock(&stats->sw_lock);
	for (i = 0; i < ARRAY_SIZE(lan9645x_port_ethtool_stats); i++)
		*data++ = c[lan9645x_port_ethtool_stats[i].idx];
	spin_unlock(&stats->sw_lock);
}

static u64 *lan9645x_stats_port_update(struct lan9645x *lan9645x, int port)
{
	return lan9645x_stats_view_idx_update(lan9645x, LAN9645X_STAT_PORTS,
					      port);
}

void lan9645x_stats_get_eth_mac_stats(struct lan9645x *lan9645x, int port,
				      struct ethtool_eth_mac_stats *m)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = lan9645x_stats_port_update(lan9645x, port);

	spin_lock(&s->sw_lock);

	switch (m->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		m->FramesTransmittedOK = c[SCNT_TX_UC] +
					 c[SCNT_TX_MC] +
					 c[SCNT_TX_BC];
		m->SingleCollisionFrames = c[SCNT_TX_COL];
		m->FramesReceivedOK = c[SCNT_RX_UC] +
				      c[SCNT_RX_MC] +
				      c[SCNT_RX_BC];
		m->FrameCheckSequenceErrors = c[SCNT_RX_CRC];
		m->OctetsTransmittedOK = c[SCNT_TX_OCT];
		m->OctetsReceivedOK = c[SCNT_RX_OCT];
		m->MulticastFramesXmittedOK = c[SCNT_TX_MC];
		m->BroadcastFramesXmittedOK = c[SCNT_TX_BC];
		m->MulticastFramesReceivedOK = c[SCNT_RX_MC];
		m->BroadcastFramesReceivedOK = c[SCNT_RX_BC];
		m->InRangeLengthErrors = c[SCNT_RX_FRAG] +
					 c[SCNT_RX_JABBER] +
					 c[SCNT_RX_CRC];
		m->OutOfRangeLengthField = c[SCNT_RX_SHORT] +
					   c[SCNT_RX_LONG];
		m->FrameTooLongErrors = c[SCNT_RX_LONG];
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		m->FramesTransmittedOK = c[SCNT_TX_PMAC_UC] +
					 c[SCNT_TX_PMAC_MC] +
					 c[SCNT_TX_PMAC_BC];
		m->FramesReceivedOK = c[SCNT_RX_PMAC_UC] +
				      c[SCNT_RX_PMAC_MC] +
				      c[SCNT_RX_PMAC_BC];
		m->FrameCheckSequenceErrors = c[SCNT_RX_PMAC_CRC];
		m->OctetsTransmittedOK = c[SCNT_TX_PMAC_OCT];
		m->OctetsReceivedOK = c[SCNT_RX_PMAC_OCT];
		m->MulticastFramesXmittedOK = c[SCNT_TX_PMAC_MC];
		m->BroadcastFramesXmittedOK = c[SCNT_TX_PMAC_BC];
		m->MulticastFramesReceivedOK = c[SCNT_RX_PMAC_MC];
		m->BroadcastFramesReceivedOK = c[SCNT_RX_PMAC_BC];
		m->InRangeLengthErrors = c[SCNT_RX_PMAC_FRAG] +
					 c[SCNT_RX_PMAC_JABBER] +
					 c[SCNT_RX_PMAC_CRC];
		m->OutOfRangeLengthField = c[SCNT_RX_PMAC_SHORT] +
					   c[SCNT_RX_PMAC_LONG];
		m->FrameTooLongErrors = c[SCNT_RX_PMAC_LONG];
		break;
	default:
		m->FramesTransmittedOK = c[SCNT_TX_UC] +
					 c[SCNT_TX_MC] +
					 c[SCNT_TX_BC] +
					 c[SCNT_TX_PMAC_UC] +
					 c[SCNT_TX_PMAC_MC] +
					 c[SCNT_TX_PMAC_BC];
		m->SingleCollisionFrames = c[SCNT_TX_COL];
		m->FramesReceivedOK = c[SCNT_RX_UC] +
				      c[SCNT_RX_MC] +
				      c[SCNT_RX_BC] +
				      c[SCNT_RX_PMAC_UC] +
				      c[SCNT_RX_PMAC_MC] +
				      c[SCNT_RX_PMAC_BC];
		m->FrameCheckSequenceErrors = c[SCNT_RX_CRC] +
					      c[SCNT_RX_PMAC_CRC];
		m->OctetsTransmittedOK = c[SCNT_TX_OCT] +
					 c[SCNT_TX_PMAC_OCT];
		m->OctetsReceivedOK = c[SCNT_RX_OCT] +
				      c[SCNT_RX_PMAC_OCT];
		m->MulticastFramesXmittedOK = c[SCNT_TX_MC] +
					      c[SCNT_TX_PMAC_MC];
		m->BroadcastFramesXmittedOK = c[SCNT_TX_BC] +
					      c[SCNT_TX_PMAC_BC];
		m->MulticastFramesReceivedOK = c[SCNT_RX_MC] +
					       c[SCNT_RX_PMAC_MC];
		m->BroadcastFramesReceivedOK = c[SCNT_RX_BC] +
					       c[SCNT_RX_PMAC_BC];
		m->InRangeLengthErrors = c[SCNT_RX_FRAG] +
					 c[SCNT_RX_JABBER] +
					 c[SCNT_RX_CRC] +
					 c[SCNT_RX_PMAC_FRAG] +
					 c[SCNT_RX_PMAC_JABBER] +
					 c[SCNT_RX_PMAC_CRC];
		m->OutOfRangeLengthField = c[SCNT_RX_SHORT] +
					   c[SCNT_RX_LONG] +
					   c[SCNT_RX_PMAC_SHORT] +
					   c[SCNT_RX_PMAC_LONG];
		m->FrameTooLongErrors = c[SCNT_RX_LONG] +
					c[SCNT_RX_PMAC_LONG];
		break;
	}

	spin_unlock(&s->sw_lock);
}

static const struct ethtool_rmon_hist_range lan9645x_rmon_ranges[] = {
	{    64,     64 },
	{   65,    127 },
	{  128,    255 },
	{  256,    511 },
	{  512,   1023 },
	{ 1024,   1526 },
	{ 1527, 0xffff },
	{}
};

void
lan9645x_stats_get_rmon_stats(struct lan9645x *lan9645x, int port,
			      struct ethtool_rmon_stats *r,
			      const struct ethtool_rmon_hist_range **ranges)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = lan9645x_stats_port_update(lan9645x, port);

	spin_lock(&s->sw_lock);

	switch (r->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		r->undersize_pkts = c[SCNT_RX_SHORT];
		r->oversize_pkts = c[SCNT_RX_LONG];
		r->fragments = c[SCNT_RX_FRAG];
		r->jabbers = c[SCNT_RX_JABBER];
		r->hist[0] = c[SCNT_RX_SZ_64];
		r->hist[1] = c[SCNT_RX_SZ_65_127];
		r->hist[2] = c[SCNT_RX_SZ_128_255];
		r->hist[3] = c[SCNT_RX_SZ_256_511];
		r->hist[4] = c[SCNT_RX_SZ_512_1023];
		r->hist[5] = c[SCNT_RX_SZ_1024_1526];
		r->hist[6] = c[SCNT_RX_SZ_JUMBO];
		r->hist_tx[0] = c[SCNT_TX_SZ_64];
		r->hist_tx[1] = c[SCNT_TX_SZ_65_127];
		r->hist_tx[2] = c[SCNT_TX_SZ_128_255];
		r->hist_tx[3] = c[SCNT_TX_SZ_256_511];
		r->hist_tx[4] = c[SCNT_TX_SZ_512_1023];
		r->hist_tx[5] = c[SCNT_TX_SZ_1024_1526];
		r->hist_tx[6] = c[SCNT_TX_SZ_JUMBO];
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		r->undersize_pkts = c[SCNT_RX_PMAC_SHORT];
		r->oversize_pkts = c[SCNT_RX_PMAC_LONG];
		r->fragments = c[SCNT_RX_PMAC_FRAG];
		r->jabbers = c[SCNT_RX_PMAC_JABBER];
		r->hist[0] = c[SCNT_RX_PMAC_SZ_64];
		r->hist[1] = c[SCNT_RX_PMAC_SZ_65_127];
		r->hist[2] = c[SCNT_RX_PMAC_SZ_128_255];
		r->hist[3] = c[SCNT_RX_PMAC_SZ_256_511];
		r->hist[4] = c[SCNT_RX_PMAC_SZ_512_1023];
		r->hist[5] = c[SCNT_RX_PMAC_SZ_1024_1526];
		r->hist[6] = c[SCNT_RX_PMAC_SZ_JUMBO];
		r->hist_tx[0] = c[SCNT_TX_PMAC_SZ_64];
		r->hist_tx[1] = c[SCNT_TX_PMAC_SZ_65_127];
		r->hist_tx[2] = c[SCNT_TX_PMAC_SZ_128_255];
		r->hist_tx[3] = c[SCNT_TX_PMAC_SZ_256_511];
		r->hist_tx[4] = c[SCNT_TX_PMAC_SZ_512_1023];
		r->hist_tx[5] = c[SCNT_TX_PMAC_SZ_1024_1526];
		r->hist_tx[6] = c[SCNT_TX_PMAC_SZ_JUMBO];
		break;
	default:
		r->undersize_pkts = c[SCNT_RX_SHORT] +
				    c[SCNT_RX_PMAC_SHORT];
		r->oversize_pkts = c[SCNT_RX_LONG] +
				   c[SCNT_RX_PMAC_LONG];
		r->fragments = c[SCNT_RX_FRAG] +
			       c[SCNT_RX_PMAC_FRAG];
		r->jabbers = c[SCNT_RX_JABBER] +
			     c[SCNT_RX_PMAC_JABBER];
		r->hist[0] = c[SCNT_RX_SZ_64] +
			     c[SCNT_RX_PMAC_SZ_64];
		r->hist[1] = c[SCNT_RX_SZ_65_127] +
			     c[SCNT_RX_PMAC_SZ_65_127];
		r->hist[2] = c[SCNT_RX_SZ_128_255] +
			     c[SCNT_RX_PMAC_SZ_128_255];
		r->hist[3] = c[SCNT_RX_SZ_256_511] +
			     c[SCNT_RX_PMAC_SZ_256_511];
		r->hist[4] = c[SCNT_RX_SZ_512_1023] +
			     c[SCNT_RX_PMAC_SZ_512_1023];
		r->hist[5] = c[SCNT_RX_SZ_1024_1526] +
			     c[SCNT_RX_PMAC_SZ_1024_1526];
		r->hist[6] = c[SCNT_RX_SZ_JUMBO] +
			     c[SCNT_RX_PMAC_SZ_JUMBO];
		r->hist_tx[0] = c[SCNT_TX_SZ_64] +
				c[SCNT_TX_PMAC_SZ_64];
		r->hist_tx[1] = c[SCNT_TX_SZ_65_127] +
				c[SCNT_TX_PMAC_SZ_65_127];
		r->hist_tx[2] = c[SCNT_TX_SZ_128_255] +
				c[SCNT_TX_PMAC_SZ_128_255];
		r->hist_tx[3] = c[SCNT_TX_SZ_256_511] +
				c[SCNT_TX_PMAC_SZ_256_511];
		r->hist_tx[4] = c[SCNT_TX_SZ_512_1023] +
				c[SCNT_TX_PMAC_SZ_512_1023];
		r->hist_tx[5] = c[SCNT_TX_SZ_1024_1526] +
				c[SCNT_TX_PMAC_SZ_1024_1526];
		r->hist_tx[6] = c[SCNT_TX_SZ_JUMBO] +
				c[SCNT_TX_PMAC_SZ_JUMBO];
		break;
	}

	spin_unlock(&s->sw_lock);

	*ranges = lan9645x_rmon_ranges;
}

/* Called in atomic context */
void lan9645x_stats_get_stats64(struct lan9645x *lan9645x, int port,
				struct rtnl_link_stats64 *stats)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = STAT_COUNTERS(lan9645x, LAN9645X_STAT_PORTS, port);

	spin_lock(&s->sw_lock);

	stats->rx_bytes = c[SCNT_RX_OCT] + c[SCNT_RX_PMAC_OCT];

	stats->rx_packets = c[SCNT_RX_SHORT] +
			    c[SCNT_RX_FRAG] +
			    c[SCNT_RX_JABBER] +
			    c[SCNT_RX_SZ_64] +
			    c[SCNT_RX_SZ_65_127] +
			    c[SCNT_RX_SZ_128_255] +
			    c[SCNT_RX_SZ_256_511] +
			    c[SCNT_RX_SZ_512_1023] +
			    c[SCNT_RX_SZ_1024_1526] +
			    c[SCNT_RX_SZ_JUMBO] +
			    c[SCNT_RX_LONG] +
			    c[SCNT_RX_PMAC_SHORT] +
			    c[SCNT_RX_PMAC_FRAG] +
			    c[SCNT_RX_PMAC_JABBER] +
			    c[SCNT_RX_PMAC_SZ_64] +
			    c[SCNT_RX_PMAC_SZ_65_127] +
			    c[SCNT_RX_PMAC_SZ_128_255] +
			    c[SCNT_RX_PMAC_SZ_256_511] +
			    c[SCNT_RX_PMAC_SZ_512_1023] +
			    c[SCNT_RX_PMAC_SZ_1024_1526] +
			    c[SCNT_RX_PMAC_SZ_JUMBO];

	stats->multicast = c[SCNT_RX_MC] + c[SCNT_RX_PMAC_MC];

	stats->rx_errors = c[SCNT_RX_SHORT] +
			   c[SCNT_RX_FRAG] +
			   c[SCNT_RX_JABBER] +
			   c[SCNT_RX_CRC] +
			   c[SCNT_RX_SYMBOL_ERR] +
			   c[SCNT_RX_LONG] +
			   c[SCNT_RX_PMAC_SHORT] +
			   c[SCNT_RX_PMAC_FRAG] +
			   c[SCNT_RX_PMAC_JABBER] +
			   c[SCNT_RX_PMAC_CRC] +
			   c[SCNT_RX_PMAC_SYMBOL_ERR] +
			   c[SCNT_RX_PMAC_LONG];

	stats->rx_dropped = c[SCNT_RX_LONG] +
			    c[SCNT_DR_LOCAL] +
			    c[SCNT_DR_TAIL] +
			    c[SCNT_RX_CAT_DROP] +
			    c[SCNT_RX_RED_PRIO_0] +
			    c[SCNT_RX_RED_PRIO_1] +
			    c[SCNT_RX_RED_PRIO_2] +
			    c[SCNT_RX_RED_PRIO_3] +
			    c[SCNT_RX_RED_PRIO_4] +
			    c[SCNT_RX_RED_PRIO_5] +
			    c[SCNT_RX_RED_PRIO_6] +
			    c[SCNT_RX_RED_PRIO_7];

	for (int i = 0; i < LAN9645X_NUM_TC; i++) {
		stats->rx_dropped += c[SCNT_DR_YELLOW_PRIO_0 + i] +
				     c[SCNT_DR_GREEN_PRIO_0 + i];
	}

	stats->tx_bytes = c[SCNT_TX_OCT] + c[SCNT_TX_PMAC_OCT];

	stats->tx_packets = c[SCNT_TX_SZ_64] +
			    c[SCNT_TX_SZ_65_127] +
			    c[SCNT_TX_SZ_128_255] +
			    c[SCNT_TX_SZ_256_511] +
			    c[SCNT_TX_SZ_512_1023] +
			    c[SCNT_TX_SZ_1024_1526] +
			    c[SCNT_TX_SZ_JUMBO] +
			    c[SCNT_TX_PMAC_SZ_64] +
			    c[SCNT_TX_PMAC_SZ_65_127] +
			    c[SCNT_TX_PMAC_SZ_128_255] +
			    c[SCNT_TX_PMAC_SZ_256_511] +
			    c[SCNT_TX_PMAC_SZ_512_1023] +
			    c[SCNT_TX_PMAC_SZ_1024_1526] +
			    c[SCNT_TX_PMAC_SZ_JUMBO];

	stats->tx_dropped = c[SCNT_TX_DROP] +
			    c[SCNT_TX_AGED] +
			    c[SCNT_TX_BUFDROP];

	stats->collisions = c[SCNT_TX_COL];

	spin_unlock(&s->sw_lock);
}

void lan9645x_stats_get_eth_phy_stats(struct lan9645x *lan9645x, int port,
				      struct ethtool_eth_phy_stats *p)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = lan9645x_stats_port_update(lan9645x, port);

	spin_lock(&s->sw_lock);

	switch (p->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		p->SymbolErrorDuringCarrier = c[SCNT_RX_SYMBOL_ERR];
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		p->SymbolErrorDuringCarrier = c[SCNT_RX_PMAC_SYMBOL_ERR];
		break;
	default:
		p->SymbolErrorDuringCarrier = c[SCNT_RX_SYMBOL_ERR] +
					      c[SCNT_RX_PMAC_SYMBOL_ERR];
		break;
	}

	spin_unlock(&s->sw_lock);
}

void
lan9645x_stats_get_eth_ctrl_stats(struct lan9645x *lan9645x, int port,
				  struct ethtool_eth_ctrl_stats *ctrl)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = lan9645x_stats_port_update(lan9645x, port);

	spin_lock(&s->sw_lock);

	switch (ctrl->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		ctrl->MACControlFramesReceived = c[SCNT_RX_CONTROL];
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		ctrl->MACControlFramesReceived = c[SCNT_RX_PMAC_CONTROL];
		break;
	default:
		ctrl->MACControlFramesReceived = c[SCNT_RX_CONTROL] +
						 c[SCNT_RX_PMAC_CONTROL];
		break;
	}

	spin_unlock(&s->sw_lock);
}

void lan9645x_stats_get_pause_stats(struct lan9645x *lan9645x, int port,
				    struct ethtool_pause_stats *ps)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = lan9645x_stats_port_update(lan9645x, port);

	spin_lock(&s->sw_lock);

	switch (ps->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		ps->tx_pause_frames = c[SCNT_TX_PAUSE];
		ps->rx_pause_frames = c[SCNT_RX_PAUSE];
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		ps->tx_pause_frames = c[SCNT_TX_PMAC_PAUSE];
		ps->rx_pause_frames = c[SCNT_RX_PMAC_PAUSE];
		break;
	default:
		ps->tx_pause_frames = c[SCNT_TX_PAUSE] + c[SCNT_TX_PMAC_PAUSE];
		ps->rx_pause_frames = c[SCNT_RX_PAUSE] + c[SCNT_RX_PMAC_PAUSE];
		break;
	}

	spin_unlock(&s->sw_lock);
}

void lan9645x_stats_get_mm_stats(struct lan9645x *lan9645x, int port,
				 struct ethtool_mm_stats *stats)
{
	struct lan9645x_stats *s = lan9645x->stats;
	u64 *c;

	c = lan9645x_stats_port_update(lan9645x, port);

	spin_lock(&s->sw_lock);

	stats->MACMergeFrameAssErrorCount = c[SCNT_RX_ASSEMBLY_ERR];
	stats->MACMergeFrameSmdErrorCount = c[SCNT_RX_SMD_ERR];
	stats->MACMergeFrameAssOkCount = c[SCNT_RX_ASSEMBLY_OK];
	stats->MACMergeFragCountRx = c[SCNT_RX_MERGE_FRAG];
	stats->MACMergeFragCountTx = c[SCNT_TX_MERGE_FRAG];
	stats->MACMergeHoldCount = c[SCNT_TX_MM_HOLD];

	spin_unlock(&s->sw_lock);
}

static void lan9645x_check_stats_work(struct work_struct *work)
{
	struct delayed_work *del_work = to_delayed_work(work);
	struct lan9645x_stats *stats;

	stats = container_of(del_work, struct lan9645x_stats, work);

	lan9645x_stats_update(stats->lan9645x);

	queue_delayed_work(stats->queue, &stats->work,
			   LAN9645X_STATS_CHECK_DELAY);
}

static int lan9645x_stats_prepare_regions(struct lan9645x *lan9645x,
					  struct lan9645x_view_stats *vstat)
{
	struct lan9645x_stat_region *regions;
	const u32 *layout = vstat->layout;
	size_t num_regions = 1;
	int i;

	for (i = 1; i < vstat->num_cnts; i++)
		if (layout[i] != layout[i - 1] + 1)
			num_regions++;

	regions = devm_kcalloc(lan9645x->dev, num_regions, sizeof(*regions),
			       GFP_KERNEL);
	if (!regions)
		return -ENOMEM;

	vstat->num_regions = num_regions;
	vstat->regions = regions;

	regions[0].base_offset = layout[0];
	regions[0].cnts_base_idx = 0;
	regions[0].cnt = 1;

	for (i = 1, num_regions = 0; i < vstat->num_cnts; i++) {
		if (layout[i] != layout[i - 1] + 1) {
			num_regions++;
			regions[num_regions].base_offset = layout[i];
			regions[num_regions].cnts_base_idx = i;
			regions[num_regions].cnt = 1;
		} else {
			regions[num_regions].cnt++;
		}
	}

	return 0;
}

static int lan9645x_view_stat_init(struct lan9645x *lan9645x,
				   struct lan9645x_view_stats *vstat,
				   const struct lan9645x_view_stats *cfg)
{
	size_t total = cfg->num_cnts * cfg->num_indexes;
	int err;

	memcpy(vstat, cfg, sizeof(*cfg));

	vstat->cnts = devm_kcalloc(lan9645x->dev, total, sizeof(u64),
				   GFP_KERNEL);
	if (!vstat->cnts)
		return -ENOMEM;

	vstat->buf = devm_kcalloc(lan9645x->dev, total, sizeof(u32),
				  GFP_KERNEL);
	if (!vstat->buf)
		return -ENOMEM;

	err = lan9645x_stats_prepare_regions(lan9645x, vstat);
	if (err)
		return err;

	vstat->stats = lan9645x->stats;

	return 0;
}

int lan9645x_stats_alloc(struct lan9645x *lan9645x)
{
	const struct lan9645x_view_stats *vs;
	struct lan9645x_stats *stats;
	int err, i;

	lan9645x->stats = devm_kzalloc(lan9645x->dev, sizeof(*stats),
				       GFP_KERNEL);
	if (!lan9645x->stats)
		return -ENOMEM;

	stats = lan9645x->stats;
	stats->lan9645x = lan9645x;

	for (i = 0; i < ARRAY_SIZE(lan9645x_view_stat_cfgs); i++) {
		vs = &lan9645x_view_stat_cfgs[i];

		if (!vs->num_cnts)
			continue;

		err = lan9645x_view_stat_init(lan9645x, &stats->view[vs->type],
					      vs);
		if (err)
			return err;
	}

	stats->queue = alloc_ordered_workqueue("%s-stats", 0,
					       dev_name(lan9645x->dev));
	if (!stats->queue)
		return -ENOMEM;

	mutex_init(&stats->hw_lock);
	spin_lock_init(&stats->sw_lock);
	INIT_DELAYED_WORK(&stats->work, lan9645x_check_stats_work);

	return 0;
}

void lan9645x_stats_free(struct lan9645x *lan9645x)
{
	cancel_delayed_work_sync(&lan9645x->stats->work);
	destroy_workqueue(lan9645x->stats->queue);
	mutex_destroy(&lan9645x->stats->hw_lock);
}

void lan9645x_stats_init(struct lan9645x *lan9645x)
{
	struct lan9645x_stats *stats = lan9645x->stats;

	queue_delayed_work(stats->queue, &stats->work,
			   LAN9645X_STATS_CHECK_DELAY);
}

void lan9645x_stats_deinit(struct lan9645x *lan9645x)
{
	cancel_delayed_work_sync(&lan9645x->stats->work);
}
