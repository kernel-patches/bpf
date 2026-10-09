// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2026 Semiconductor Components Industries, LLC ("onsemi").
 * onsemi's S2500 10BASE-T1S MAC-PHY driver
 */

#include <linux/ethtool.h>
#include <linux/phy.h>

#include "s2500_hw_def.h"

#define S2500_NUM_REGS			38
#define S2500_REGDUMP_LEN		(sizeof(u32) * (S2500_NUM_REGS * 2))

#define S2500_NUM_MAC_STATS		1
#define S2500_NUM_RMON_STATS		12

struct s2500_reg_map {
	u16 reg;
	u8 mms;
};

static const struct s2500_reg_map s2500_reg_map[S2500_NUM_REGS] = {
	{ S2500_REG_VS_ONIPVER,      OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_TWEAKS1,      OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_PLCAEXT,      OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_PMATUNE0,     OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_PMATUNE1,     OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_T1SWUPTUNE,   OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_HDD,          OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_DCQ_TOID,     OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_DCQ_SQI,      OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_DCQ_SQI_PLUS, OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_HDD_TUNE1,    OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_HDD_TUNE2,    OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_HDD_TUNE3,    OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_WS_STATUS_0,  OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_WS_CTRL_0,    OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_WS_STATUS_1,  OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_WS_CTRL_1,    OA_TC6_PHY_C45_VS_PLCA_MMS4 },
	{ S2500_REG_VS_MIIMIRQE,     OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_MIIMIRQS,     OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_DIOCFG0,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CHIPID,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_TWEAKS2,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_MACID0,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_MACID1,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_NVM_HEALTH,   OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_PTP_SEC,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_PTPNSEC,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_PTP_SETSEC,   OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_SETNSEC,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_PTP_ADJ,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CMPCTL,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CMPSEC,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CMPNSEC,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CMPPER,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CAPCTL,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CAPSEC,       OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_CAPNSEC,      OA_TC6_PHY_C45_VS_MMS12 },
	{ S2500_REG_VS_BCNCNT,       OA_TC6_PHY_C45_VS_MMS12 },
};

enum s2500_stat_idx {
	S2500_MSTOCTECTSTX_IDX = 0,
	S2500_MSTFRAMESTXOK_IDX,
	S2500_MSTBCASTTXOK_IDX,
	S2500_MSTMCASTTXOK_IDX,
	S2500_MSTFRAMESTX64_IDX,
	S2500_MSTFRAMESTX65_IDX,
	S2500_MSTFRAMESTX128_IDX,
	S2500_MSTFRAMESTX256_IDX,
	S2500_MSTFRAMESTX512_IDX,
	S2500_MSTFRAMESTX1024_IDX,
	S2500_MSTTXUNDEFLOW_IDX,
	S2500_MSTSINGLECOL_IDX,
	S2500_MSTMULTICOL_IDX,
	S2500_MSTEXCESSCOL_IDX,
	S2500_MSTDEFERREDTX_IDX,
	S2500_MSTCRSERR_IDX,
	S2500_MSTOCTECTSRX_IDX,
	S2500_MSTFRAMESRXOK_IDX,
	S2500_MSTBCASTRXOK_IDX,
	S2500_MSTMCASTRXOK_IDX,
	S2500_MSTFRAMESRX64_IDX,
	S2500_MSTFRAMESRX65_IDX,
	S2500_MSTFRAMESRX128_IDX,
	S2500_MSTFRAMESRX256_IDX,
	S2500_MSTFRAMESRX512_IDX,
	S2500_MSTFRAMESRX1024_IDX,
	S2500_MSTRUNTSERR_IDX,
	S2500_MSTRXTOOLONG_IDX,
	S2500_MSTFCSERRS_IDX,
	S2500_MSTSYMBOLERRS_IDX,
	S2500_MSTALIGNERRS_IDX,
	S2500_MSTRXOVERFLOW_IDX,
	S2500_MSTRXDROPPED_IDX,
};

static const char s2500_mac_stat_strings[][ETH_GSTRING_LEN] = {
	"rx_mismatch_drops",
};

static const u8 s2500_mac_stat_map[S2500_NUM_MAC_STATS] = {
	S2500_MSTRXDROPPED_IDX,
};

static const u8 s2500_rmon_stat_map[S2500_NUM_RMON_STATS] = {
	S2500_MSTFRAMESTX64_IDX,
	S2500_MSTFRAMESTX65_IDX,
	S2500_MSTFRAMESTX128_IDX,
	S2500_MSTFRAMESTX256_IDX,
	S2500_MSTFRAMESTX512_IDX,
	S2500_MSTFRAMESTX1024_IDX,
	S2500_MSTFRAMESRX64_IDX,
	S2500_MSTFRAMESRX65_IDX,
	S2500_MSTFRAMESRX128_IDX,
	S2500_MSTFRAMESRX256_IDX,
	S2500_MSTFRAMESRX512_IDX,
	S2500_MSTFRAMESRX1024_IDX,
};

static const struct ethtool_rmon_hist_range s2500_rmon_hist_ranges[] = {
	{ 64, 64 },
	{ 65, 127 },
	{ 128, 255 },
	{ 256, 511 },
	{ 512, 1023 },
	{ 1024, 2000 },
	{ },
};

#define S2500_MAC_STATS_LEN ARRAY_SIZE(s2500_mac_stat_strings)
static_assert(S2500_MAC_STATS_LEN == S2500_NUM_MAC_STATS);
static_assert(ARRAY_SIZE(s2500_mac_stat_map) == S2500_NUM_MAC_STATS);
static_assert(ARRAY_SIZE(s2500_rmon_stat_map) == S2500_NUM_RMON_STATS);

#define STAT_REG_OFFSET(x) ((S2500_REG_MAC_ST##x) - \
			   S2500_REG_MAC_FIRST_STAT)

static void s2500_update_stats(struct s2500_info *priv)
{
	u64 *data = priv->stats_data;
	u32 *regs, *rptr, addr;
	int ret;

	if (time_is_after_jiffies(priv->stats_read_at +
				  S2500_STATS_CACHE_PERIOD))
		return;

	regs = kmalloc_array(S2500_NUM_STAT_REGS, sizeof(u32), GFP_KERNEL);
	if (!regs)
		return;

	addr = FIELD_PREP(S2500_REG_MMS_MASK, OA_TC6_MAC_MMS1) |
			  S2500_REG_MAC_STOCTECTSTXL;
	ret = oa_tc6_read_registers(priv->tc6, addr, regs,
				    S2500_NUM_STAT_REGS);
	if (ret)
		goto out;

	priv->stats_read_at = jiffies;
	rptr = regs;

	/* TX bytes is a 64-bit value that is stored in two regs.
	 * When lower 32 bits are read from OCTETS-L register,
	 * upper bits are sampled and stored in OCTETS-H register.
	 * Request to read multiple registers reads OCTETS-L first.
	 * This way, counter value is read in an atomic manner.
	 */
	*(data++) += ((u64)*rptr) | (((u64)*(rptr + 1)) << 32);

	/* Rest are 32-bit values until RX bytes register. */
	for (rptr += 2; (rptr - regs) < STAT_REG_OFFSET(OCTECTSRXL); ++rptr)
		*(data++) += *rptr;

	/* RX bytes is a 64-bit value that is stored in two regs.
	 * Like TX bytes counter, value is read atomically from
	 * registers.
	 */
	*(data++) += ((u64)*rptr) | (((u64)*(rptr + 1)) << 32);

	for (rptr += 2; (rptr - regs) < S2500_NUM_STAT_REGS; ++rptr)
		*(data++) += *rptr;
out:
	kfree(regs);
}

static void s2500_get_drvinfo(struct net_device *ndev,
			      struct ethtool_drvinfo *info)
{
	struct s2500_info *priv = netdev_priv(ndev);

	strscpy(info->driver, DRV_NAME, sizeof(info->driver));
	strscpy(info->bus_info, dev_name(&priv->spi->dev),
		sizeof(info->bus_info));
}

static int s2500_get_sset_count(struct net_device *ndev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return S2500_MAC_STATS_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

static void s2500_get_strings(struct net_device *ndev, u32 stringset,
			      u8 *buf)
{
	switch (stringset) {
	case ETH_SS_STATS:
		memcpy(buf, s2500_mac_stat_strings,
		       S2500_MAC_STATS_LEN * ETH_GSTRING_LEN);
		break;
	}
}

static void s2500_get_ethtool_stats(struct net_device *ndev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct s2500_info *priv = netdev_priv(ndev);
	int i;

	s2500_update_stats(priv);
	for (i = 0; i < S2500_NUM_MAC_STATS; i++)
		data[i] = priv->stats_data[s2500_mac_stat_map[i]];
}

static void s2500_get_eth_mac_stats(struct net_device *ndev,
				    struct ethtool_eth_mac_stats *mac_stats)
{
	struct s2500_info *priv = netdev_priv(ndev);
	const u64 *st;

	if (mac_stats->src != ETHTOOL_MAC_STATS_SRC_AGGREGATE)
		return;

	s2500_update_stats(priv);
	st = priv->stats_data;

	mac_stats->OctetsTransmittedOK = st[S2500_MSTOCTECTSTX_IDX];
	mac_stats->FramesTransmittedOK = st[S2500_MSTFRAMESTXOK_IDX];
	mac_stats->BroadcastFramesXmittedOK = st[S2500_MSTBCASTTXOK_IDX];
	mac_stats->MulticastFramesXmittedOK = st[S2500_MSTMCASTTXOK_IDX];
	mac_stats->SingleCollisionFrames = st[S2500_MSTSINGLECOL_IDX];
	mac_stats->MultipleCollisionFrames = st[S2500_MSTMULTICOL_IDX];
	mac_stats->FramesAbortedDueToXSColls = st[S2500_MSTEXCESSCOL_IDX];
	mac_stats->FramesWithDeferredXmissions = st[S2500_MSTDEFERREDTX_IDX];
	mac_stats->CarrierSenseErrors = st[S2500_MSTCRSERR_IDX];
	mac_stats->FramesLostDueToIntMACXmitError =
		st[S2500_MSTTXUNDEFLOW_IDX];
	mac_stats->OctetsReceivedOK = st[S2500_MSTOCTECTSRX_IDX];
	mac_stats->FramesReceivedOK = st[S2500_MSTFRAMESRXOK_IDX];
	mac_stats->BroadcastFramesReceivedOK = st[S2500_MSTBCASTRXOK_IDX];
	mac_stats->MulticastFramesReceivedOK = st[S2500_MSTMCASTRXOK_IDX];
	mac_stats->FrameTooLongErrors = st[S2500_MSTRXTOOLONG_IDX];
	mac_stats->FrameCheckSequenceErrors = st[S2500_MSTFCSERRS_IDX];
	mac_stats->AlignmentErrors = st[S2500_MSTALIGNERRS_IDX];
	mac_stats->FramesLostDueToIntMACRcvError =
		st[S2500_MSTRXOVERFLOW_IDX];
}

static void s2500_get_eth_phy_stats(struct net_device *ndev,
				    struct ethtool_eth_phy_stats *phy_stats)
{
	struct s2500_info *priv = netdev_priv(ndev);

	if (phy_stats->src != ETHTOOL_MAC_STATS_SRC_AGGREGATE)
		return;

	s2500_update_stats(priv);
	phy_stats->SymbolErrorDuringCarrier =
		priv->stats_data[S2500_MSTSYMBOLERRS_IDX];
}

static void s2500_rmon_stats(struct net_device *ndev,
			     struct ethtool_rmon_stats *rmon_stats,
			     const struct ethtool_rmon_hist_range **ranges)
{
	struct s2500_info *priv = netdev_priv(ndev);
	u8 offset;
	int i;

	if (rmon_stats->src != ETHTOOL_MAC_STATS_SRC_AGGREGATE)
		return;

	s2500_update_stats(priv);

	rmon_stats->undersize_pkts = priv->stats_data[S2500_MSTRUNTSERR_IDX];
	rmon_stats->oversize_pkts = priv->stats_data[S2500_MSTRXTOOLONG_IDX];

	for (i = 0; i < 6; i++) {
		offset = s2500_rmon_stat_map[i];
		rmon_stats->hist_tx[i] = priv->stats_data[offset];
	}

	for (i = 0; i < 6; i++) {
		offset = s2500_rmon_stat_map[i + 6];
		rmon_stats->hist[i] = priv->stats_data[offset];
	}

	*ranges = s2500_rmon_hist_ranges;
}

static int s2500_get_ts_info(struct net_device *ndev,
			     struct kernel_ethtool_ts_info *ts_info)
{
	struct s2500_info *priv = netdev_priv(ndev);

	return oa_tc6_get_ts_info(priv->tc6, ts_info);
}

static int s2500_get_regs_len(struct net_device *dev)
{
	return S2500_REGDUMP_LEN;
}

static void s2500_get_regs(struct net_device *ndev,
			   struct ethtool_regs *regs, void *p)
{
	struct s2500_info *priv = netdev_priv(ndev);
	__be32 *pbuff = p;
	int ret = 0;
	u32 val;
	u16 reg;
	u8 mms;
	int i;

	regs->version = 0;
	memset(p, 0, S2500_REGDUMP_LEN);

	if (!netif_running(ndev))
		return;

	for (i = 0; i < S2500_NUM_REGS; i++) {
		val = 0;
		reg = s2500_reg_map[i].reg;
		mms = s2500_reg_map[i].mms;
		ret = oa_tc6_read_register_mms(priv->tc6, mms, reg,
					       &val);

		/* Write a pattern to indicate failure */
		if (ret)
			val = 0xDEADC0DE;
		*pbuff++ = cpu_to_be32(((u32)mms << 16) | reg);
		*pbuff++ = cpu_to_be32(val);
	}
}

static void s2500_get_ts_stats(struct net_device *ndev,
			       struct ethtool_ts_stats *ts_stats)
{
	struct s2500_info *priv = netdev_priv(ndev);

	oa_tc6_get_ts_stats(priv->tc6, ts_stats);
}

const struct ethtool_ops s2500_ethtool_ops = {
	.get_drvinfo = s2500_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_link_ksettings = phy_ethtool_get_link_ksettings,
	.set_link_ksettings = phy_ethtool_set_link_ksettings,
	.get_ts_stats = s2500_get_ts_stats,
	.get_sset_count = s2500_get_sset_count,
	.get_strings = s2500_get_strings,
	.get_ethtool_stats = s2500_get_ethtool_stats,
	.get_eth_mac_stats = s2500_get_eth_mac_stats,
	.get_eth_phy_stats = s2500_get_eth_phy_stats,
	.get_rmon_stats = s2500_rmon_stats,
	.get_ts_info = s2500_get_ts_info,
	.get_regs_len = s2500_get_regs_len,
	.get_regs = s2500_get_regs,
};

