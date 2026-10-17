// SPDX-License-Identifier: GPL-2.0+
/*
 * OPEN Alliance 10BASE‑T1x MAC‑PHY Serial Interface framework
 *
 * Author: Selva Rajagopal <selvamani.rajagopal@onsemi.com>
 */

#include <linux/bitfield.h>
#include <linux/iopoll.h>
#include <linux/mdio.h>
#include <linux/phy.h>
#include <linux/oa_tc6.h>

#include "oa_tc6_std_def.h"

static int oa_tc6_set_hwtstamp_settings(struct oa_tc6 *tc6,
					const struct hwtstamp_config *ts_cfg)
{
	u32 regs[CFG0_TO_IMASK0_REG_COUNT];
	u32 cfg0, irqm, status0;
	bool disabled;
	int ret;

	if (tc6->ts_config.flags == ts_cfg->flags &&
	    tc6->ts_config.tx_type == ts_cfg->tx_type &&
	    tc6->ts_config.rx_filter == ts_cfg->rx_filter)
		return 0;

	spin_lock_bh(&tc6->tx_skb_lock);
	disabled = tc6->disable_traffic;
	spin_unlock_bh(&tc6->tx_skb_lock);
	if (disabled)
		return -EIO;

	/* CONFIG0, STATUS0 and INT_MASK0 span one register block, so a
	 * single control transaction covers all three.
	 */
	ret = oa_tc6_read_registers(tc6, OA_TC6_REG_CONFIG0, regs,
				    ARRAY_SIZE(regs));
	if (ret) {
		dev_err(&tc6->spi->dev, "Failed to read CFG0 block\n");
		goto out;
	}

	cfg0 = regs[CFG0_VAL_OFFSET];
	status0 = regs[STATUS0_VAL_OFFSET];
	irqm = regs[IRQM_VAL_OFFSET];

	/* Hardware timestamp feature supports 64-bit timestamp only */
	if (ts_cfg->tx_type == HWTSTAMP_TX_ON ||
	    ts_cfg->rx_filter == HWTSTAMP_FILTER_ALL)
		cfg0 |= (OA_TC6_CONFIG0_FTSE_ENABLE |
			 OA_TC6_CONFIG0_FTSS_64BIT_TSTAMP);
	else
		cfg0 &= ~OA_TC6_CONFIG0_FTSE_ENABLE;

	if (ts_cfg->tx_type == HWTSTAMP_TX_ON)
		irqm &= ~OA_TC6_INT_MASK0_TTSCA_MASK;
	else
		irqm |= OA_TC6_INT_MASK0_TTSCA_MASK;

	/* STATUS0 is write-one-to-clear, so this acknowledges a capture
	 * without delivering its timestamp. Skip it while TX timestamping
	 * stays enabled, where a capture may still be outstanding.
	 */
	status0 &= OA_TC6_STATUS0_TTSCA_MASK;
	if (status0 && (tc6->ts_config.tx_type != HWTSTAMP_TX_ON ||
			ts_cfg->tx_type != HWTSTAMP_TX_ON)) {
		ret = oa_tc6_write_register(tc6, OA_TC6_REG_STATUS0,
					    status0);
		if (ret) {
			dev_err(&tc6->spi->dev,
				"failed to write STATUS0 register\n");
			goto out;
		}
	}

	ret = oa_tc6_write_register(tc6, OA_TC6_REG_INT_MASK0, irqm);
	if (ret) {
		dev_err(&tc6->spi->dev, "failed to write IRQM register\n");
		goto out;
	}

	ret = oa_tc6_write_register(tc6, OA_TC6_REG_CONFIG0, cfg0);
	if (ret) {
		dev_err(&tc6->spi->dev, "failed to write CFG0 register\n");
		goto out;
	}
	spin_lock_bh(&tc6->tx_skb_lock);
	tc6->ts_config = *ts_cfg;
	if (cfg0 & OA_TC6_CONFIG0_FTSE_ENABLE)
		tc6->hw_tstamp_enabled = true;
	else
		tc6->hw_tstamp_enabled = false;
	spin_unlock_bh(&tc6->tx_skb_lock);

	/* The TX timestamp completion interrupt is masked now. Time
	 * to release the queued skbs.
	 */
	if (ts_cfg->tx_type != HWTSTAMP_TX_ON)
		oa_tc6_cleanup_tx_tstamp_skbs(tc6);
out:
	return ret;
}

/**
 * oa_tc6_hwtstamp_get - gets hardware timestamp config
 * @tc6: oa_tc6 struct.
 * @cfg: kernel copy of hardware timestamp config
 */
void oa_tc6_hwtstamp_get(struct oa_tc6 *tc6,
			 struct kernel_hwtstamp_config *cfg)
{
	hwtstamp_config_to_kernel(cfg, &tc6->ts_config);
}
EXPORT_SYMBOL_GPL(oa_tc6_hwtstamp_get);

/**
 * oa_tc6_hwtstamp_set - sets hardware timestamp config
 * @tc6: oa_tc6 struct.
 * @cfg: kernel copy of hardware timestamp config
 *
 * Return: 0 on success otherwise failed.
 */
int oa_tc6_hwtstamp_set(struct oa_tc6 *tc6,
			struct kernel_hwtstamp_config *cfg)
{
	struct hwtstamp_config ts_cfg;
	int ret;

	if (!netif_running(tc6->netdev))
		return -EIO;

	/* Set only when STDCAP advertised the capability and the PHC
	 * registered, which is what ethtool -T reports.
	 */
	if (!tc6->ptp_clock)
		return -EOPNOTSUPP;

	switch (cfg->tx_type) {
	case HWTSTAMP_TX_OFF:
	case HWTSTAMP_TX_ON:
		break;
	default:
		return -ERANGE;
	}

	switch (cfg->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_NTP_ALL:
		break;
	default:
		return -ERANGE;
	}

	hwtstamp_config_from_kernel(&ts_cfg, cfg);

	/* Supports timestamping all traffic */
	if (cfg->rx_filter != HWTSTAMP_FILTER_NONE ||
	    cfg->tx_type == HWTSTAMP_TX_ON)
		ts_cfg.rx_filter = HWTSTAMP_FILTER_ALL;

	ret = oa_tc6_set_hwtstamp_settings(tc6, &ts_cfg);
	if (ret)
		return ret;

	/* Report what was programmed, not asked. */
	cfg->rx_filter = ts_cfg.rx_filter;

	return 0;
}
EXPORT_SYMBOL_GPL(oa_tc6_hwtstamp_set);

/**
 * oa_tc6_get_ts_stats - Provides timestamping stats
 * @tc6: oa_tc6 struct.
 * @stats: ethtool data structure to fill in
 */
void oa_tc6_get_ts_stats(struct oa_tc6 *tc6,
			 struct ethtool_ts_stats *stats)
{
	stats->pkts = tc6->tx_hwtstamp_pkts;
	stats->err = tc6->tx_hwtstamp_err;
	stats->lost = tc6->tx_hwtstamp_lost;
}
EXPORT_SYMBOL_GPL(oa_tc6_get_ts_stats);

/**
 * oa_tc6_get_ts_info - Provides timestamp info for ethtool
 * @tc6: oa_tc6 struct.
 * @info: ethtool timestamping info structure
 *
 * Return: 0 on success otherwise failed.
 */
int oa_tc6_get_ts_info(struct oa_tc6 *tc6,
		       struct kernel_ethtool_ts_info *info)
{
	if (!tc6->ptp_clock)
		return ethtool_op_get_ts_info(tc6->netdev, info);

	info->so_timestamping = SOF_TIMESTAMPING_RAW_HARDWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE;
	info->phc_index = ptp_clock_index(tc6->ptp_clock);
	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			   BIT(HWTSTAMP_FILTER_ALL);
	return 0;
}
EXPORT_SYMBOL_GPL(oa_tc6_get_ts_info);
