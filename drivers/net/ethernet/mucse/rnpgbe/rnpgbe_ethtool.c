// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include <linux/ethtool.h>
#include <linux/linkmode.h>
#include <linux/pci.h>

#include "rnpgbe.h"
#include "rnpgbe_mbx_fw.h"

static const struct {
	u32 fw_mode;
	u32 ethtool_mode;
} rnpgbe_tp_modes[] = {
	{ RNPGBE_FW_ADV_10_HALF, ETHTOOL_LINK_MODE_10baseT_Half_BIT },
	{ RNPGBE_FW_ADV_10_FULL, ETHTOOL_LINK_MODE_10baseT_Full_BIT },
	{ RNPGBE_FW_ADV_100_HALF, ETHTOOL_LINK_MODE_100baseT_Half_BIT },
	{ RNPGBE_FW_ADV_100_FULL, ETHTOOL_LINK_MODE_100baseT_Full_BIT },
	{ RNPGBE_FW_ADV_1000_FULL, ETHTOOL_LINK_MODE_1000baseT_Full_BIT },
};

static void rnpgbe_link_modes(unsigned long *modes, u32 fw_modes)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rnpgbe_tp_modes); i++) {
		if (fw_modes & rnpgbe_tp_modes[i].fw_mode)
			linkmode_set_bit(rnpgbe_tp_modes[i].ethtool_mode,
					 modes);
	}
}

/**
 * rnpgbe_init_link_config - Cache firmware link capabilities and configuration
 * @hw: hardware information structure
 *
 * Query before port-up: repeated GET_LANE_STATUS commands can prevent
 * firmware from completing forced 10 Mb/s link setup. Runtime link state
 * comes from link events instead.
 *
 * Return: 0 on success, negative errno on failure
 */
int rnpgbe_init_link_config(struct mucse_hw *hw)
{
	struct mucse_link_info info;
	int err;

	err = mucse_mbx_get_link(hw, &info);
	if (err)
		return err;

	hw->link_config.supported = le32_to_cpu(info.supported);
	hw->link_config.advertising = le32_to_cpu(info.advertising);
	hw->link_config.status = le16_to_cpu(info.status);
	hw->link_config.phy_addr = info.phy_addr;

	return 0;
}

static int rnpgbe_get_link_ksettings(struct net_device *netdev,
				     struct ethtool_link_ksettings *cmd)
{
	struct mucse *mucse = netdev_priv(netdev);
	struct mucse_hw *hw = &mucse->hw;
	u32 supported, advertising;
	unsigned long flags;
	u16 status;
	int mode;

	status = hw->link_config.status;
	supported = hw->link_config.supported;
	advertising = hw->link_config.advertising;
	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);
	ethtool_link_ksettings_zero_link_mode(cmd, lp_advertising);
	cmd->base.autoneg = AUTONEG_DISABLE;
	cmd->base.speed = SPEED_UNKNOWN;
	cmd->base.duplex = DUPLEX_UNKNOWN;
	cmd->base.eth_tp_mdix = ETH_TP_MDI_INVALID;
	spin_lock_irqsave(&mucse->link_lock, flags);
	if (netif_carrier_ok(netdev) && hw->link) {
		cmd->base.speed = hw->speed;
		cmd->base.duplex = hw->duplex ?
				   DUPLEX_FULL : DUPLEX_HALF;
		if (status & MUCSE_LINK_TP)
			cmd->base.eth_tp_mdix = hw->mdix;
	}
	spin_unlock_irqrestore(&mucse->link_lock, flags);

	if (status & MUCSE_LINK_TP) {
		rnpgbe_link_modes(cmd->link_modes.supported, supported);
		rnpgbe_link_modes(cmd->link_modes.advertising, advertising);
		ethtool_link_ksettings_add_link_mode(cmd, supported, TP);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, TP);
		ethtool_link_ksettings_add_link_mode(cmd, supported, Autoneg);
		if (status & MUCSE_LINK_AUTONEG) {
			cmd->base.autoneg = AUTONEG_ENABLE;
			ethtool_link_ksettings_add_link_mode(cmd, advertising,
							     Autoneg);
		}
		cmd->base.port = PORT_TP;
		cmd->base.phy_address = hw->link_config.phy_addr;
		cmd->base.eth_tp_mdix_ctrl = hw->mdix_ctrl;
	} else {
		if (status & MUCSE_LINK_BACKPLANE) {
			mode = ETHTOOL_LINK_MODE_1000baseKX_Full_BIT;
			ethtool_link_ksettings_add_link_mode(cmd, supported,
							     Backplane);
			ethtool_link_ksettings_add_link_mode(cmd, advertising,
							     Backplane);
			cmd->base.port = PORT_NONE;
		} else {
			mode = ETHTOOL_LINK_MODE_1000baseX_Full_BIT;
			ethtool_link_ksettings_add_link_mode(cmd, supported,
							     FIBRE);
			ethtool_link_ksettings_add_link_mode(cmd, advertising,
							     FIBRE);
			cmd->base.port = PORT_FIBRE;
		}
		if (supported & RNPGBE_FW_ADV_1000_FULL)
			linkmode_set_bit(mode, cmd->link_modes.supported);
		if (advertising & RNPGBE_FW_ADV_1000_FULL)
			linkmode_set_bit(mode, cmd->link_modes.advertising);
	}

	if (cmd->base.autoneg == AUTONEG_DISABLE) {
		cmd->base.speed = hw->link_config.speed;
		cmd->base.duplex = hw->link_config.duplex;
	}

	return 0;
}

static u32 rnpgbe_fw_link_modes(const unsigned long *modes)
{
	u32 fw_modes = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(rnpgbe_tp_modes); i++) {
		if (linkmode_test_bit(rnpgbe_tp_modes[i].ethtool_mode, modes))
			fw_modes |= rnpgbe_tp_modes[i].fw_mode;
	}

	return fw_modes;
}

static int rnpgbe_set_link_ksettings(struct net_device *netdev,
				     const struct ethtool_link_ksettings *cmd)
{
	struct ethtool_link_ksettings settings = {};
	struct mucse *mucse = netdev_priv(netdev);
	u8 mdix = cmd->base.eth_tp_mdix_ctrl;
	u32 advertising, mode, supported;
	bool autoneg;
	int err;

	if (cmd->base.autoneg != AUTONEG_ENABLE &&
	    cmd->base.autoneg != AUTONEG_DISABLE)
		return -EINVAL;
	autoneg = cmd->base.autoneg == AUTONEG_ENABLE;
	if (!mdix)
		mdix = mucse->hw.mdix_ctrl;
	if (mdix != ETH_TP_MDI && mdix != ETH_TP_MDI_X &&
	    mdix != ETH_TP_MDI_AUTO)
		return -EINVAL;

	err = rnpgbe_get_link_ksettings(netdev, &settings);
	if (err)
		return err;
	if (settings.base.port != PORT_TP)
		return -EOPNOTSUPP;

	supported = rnpgbe_fw_link_modes(settings.link_modes.supported);
	advertising = rnpgbe_fw_link_modes(settings.link_modes.advertising);
	if (autoneg) {
		if (!linkmode_subset(cmd->link_modes.advertising,
				     settings.link_modes.supported))
			return -EINVAL;
		advertising = rnpgbe_fw_link_modes(cmd->link_modes.advertising);
		if (!advertising)
			return -EINVAL;
	} else {
		if (cmd->base.duplex != DUPLEX_FULL &&
		    cmd->base.duplex != DUPLEX_HALF)
			return -EINVAL;
		switch (cmd->base.speed) {
		case SPEED_10:
			mode = cmd->base.duplex == DUPLEX_FULL ?
				RNPGBE_FW_ADV_10_FULL : RNPGBE_FW_ADV_10_HALF;
			break;
		case SPEED_100:
			mode = cmd->base.duplex == DUPLEX_FULL ?
				RNPGBE_FW_ADV_100_FULL : RNPGBE_FW_ADV_100_HALF;
			break;
		default:
			return -EINVAL;
		}
		if (!(supported & mode))
			return -EINVAL;
	}

	err = mucse_mbx_set_link(&mucse->hw, advertising, autoneg,
				 autoneg ? 0 : cmd->base.speed,
				 autoneg ? 0 : cmd->base.duplex, mdix);
	if (!err) {
		mucse->hw.mdix_ctrl = mdix;
		mucse->hw.link_config.advertising = advertising;
		mucse->hw.link_config.speed = autoneg ?
			SPEED_UNKNOWN : cmd->base.speed;
		mucse->hw.link_config.duplex = autoneg ?
			DUPLEX_UNKNOWN : cmd->base.duplex;
		if (autoneg)
			mucse->hw.link_config.status |= MUCSE_LINK_AUTONEG;
		else
			mucse->hw.link_config.status &= ~MUCSE_LINK_AUTONEG;
	}

	return err;
}

static void rnpgbe_get_drvinfo(struct net_device *netdev,
			       struct ethtool_drvinfo *info)
{
	struct mucse *mucse = netdev_priv(netdev);
	u32 version = mucse->hw.fw_version;

	strscpy(info->driver, KBUILD_MODNAME);
	strscpy(info->bus_info, pci_name(mucse->pdev));
	snprintf(info->fw_version, sizeof(info->fw_version), "%u.%u.%u.%u",
		 version >> 24, (version >> 16) & 0xff,
		 (version >> 8) & 0xff, version & 0xff);
}

const struct ethtool_ops rnpgbe_ethtool_ops = {
	.get_drvinfo = rnpgbe_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_link_ksettings = rnpgbe_get_link_ksettings,
	.set_link_ksettings = rnpgbe_set_link_ksettings,
	.get_sset_count = rnpgbe_get_sset_count,
	.get_strings = rnpgbe_get_strings,
	.get_ethtool_stats = rnpgbe_get_ethtool_stats,
};
