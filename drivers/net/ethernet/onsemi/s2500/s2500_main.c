// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2026 Semiconductor Components Industries, LLC ("onsemi").
 * onsemi's S2500 10BASE-T1S MAC-PHY driver
 */

#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/irqchip.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/bitrev.h>
#include <linux/phy.h>

#include "s2500_hw_def.h"

/* Initializes the net device MAC address by reading the UID stored
 * into the device internal non-volatile memory.
 */
static int s2500_read_mac_from_nvmem(struct s2500_info *priv)
{
	u8 mms = OA_TC6_PHY_C45_VS_MMS12;
	u8 addr[ETH_ALEN];
	u32 mac1 = 0;
	u32 mac0 = 0;
	u32 val;
	int ret;

	ret = oa_tc6_read_register_mms(priv->tc6, mms,
				       S2500_REG_VS_MACID1, &mac1);
	if (ret)
		return ret;

	ret = oa_tc6_read_register_mms(priv->tc6, mms,
				       S2500_REG_VS_MACID0, &mac0);
	if (ret)
		return ret;

	/* Pre-production parts may have 0 */
	if (mac0 == 0 && mac1 == 0)
		return -ENXIO;

	ret = oa_tc6_read_register(priv->tc6, S2500_REG_PHYID, &val);
	if (ret)
		return ret;

	val = (val & S2500_PHYID_OUI_MASK) >> S2500_PHYID_OUI_SHIFT;

	/* Mapping for bits from PHY ID register to OUI as give below.
	 * - PHY-ID[10:17] provides OUI[16:23]
	 * - PHY-ID[18:25] provides OUI[8:15]
	 * - PHY-ID[26:31] provides OUI[2:7]
	 *
	 * Hardware presents OUI such a way that this requires not just
	 * byte level swap, bit level swap is needed as well.
	 */
	addr[0] = bitrev8(FIELD_GET(S2500_PHYID_OUI_MASK0, val));
	addr[1] = bitrev8(FIELD_GET(S2500_PHYID_OUI_MASK1, val));
	addr[2] = bitrev8(FIELD_GET(S2500_PHYID_OUI_MASK2, val));

	addr[3] = FIELD_GET(S2500_VS_MACID1_BYTE3_MASK, mac1);
	addr[4] = FIELD_GET(S2500_VS_MACID0_BYTE4_MASK, mac0);
	addr[5] = FIELD_GET(S2500_VS_MACID0_BYTE5_MASK, mac0);

	__dev_addr_set(priv->ndev, addr, ETH_ALEN);
	priv->ndev->addr_assign_type = NET_ADDR_PERM;
	return ret;
}

/* Writes MAC address to macphy registers */
static int s2500_set_mac_filter(struct net_device *ndev, const u8 *mac)
{
	struct s2500_info *priv = netdev_priv(ndev);
	u8 mms = OA_TC6_MAC_MMS1;
	u32 val;
	int ret;

	/* Set unicast address filter */
	ret = oa_tc6_write_register_mms(priv->tc6, mms,
					S2500_REG_MAC_ADDRMASKL(0),
					0xffffffff);
	if (ret)
		return ret;

	ret = oa_tc6_write_register_mms(priv->tc6, mms,
					S2500_REG_MAC_ADDRMASKH(0),
					0xffff);
	if (ret)
		return ret;

	val = get_unaligned_be32(&mac[2]);

	ret = oa_tc6_write_register_mms(priv->tc6, mms,
					S2500_REG_MAC_ADDRFILTL(0),
					val);
	if (ret)
		return ret;

	val = S2500_MAC_ADDRFILT_ENABLE | get_unaligned_be16(mac);

	return oa_tc6_write_register_mms(priv->tc6, mms,
					 S2500_REG_MAC_ADDRFILTH(0),
					 val);
}

static int s2500_mac_ctrl_modify_bits(struct s2500_info *priv,
				      u32 in_bits, bool clr)
{
	u32 reg = S2500_REG_MAC_CTRL;
	u8 mms = OA_TC6_MAC_MMS1;
	u32 rval = 0;
	u32 wval = 0;
	int ret;

	ret = oa_tc6_read_register_mms(priv->tc6, mms, reg, &rval);
	if (ret)
		return ret;

	if (clr)
		wval = rval & ~in_bits;
	else
		wval = rval | in_bits;
	if (rval != wval)
		ret = oa_tc6_write_register_mms(priv->tc6, mms,
						reg, wval);
	return ret;
}

static int s2500_init(struct s2500_info *priv)
{
	u32 val;
	int ret;

	/* Configure MAC-PHY's behavior */
	val = OA_TC6_CONFIG0_SYNC | S2500_CONFIG0_RXCTE |
	      (S2500_CONFIG0_TXCTHRESH_8 <<
	      S2500_CONFIG0_TXCTHRESH_SHIFT) |
	      (S2500_CONFIG0_CPS_64 << S2500_CONFIG0_CPS_SHIFT) |
	      OA_TC6_CONFIG0_FTSS_64BIT_TSTAMP;

	ret = oa_tc6_write_register(priv->tc6, OA_TC6_REG_CONFIG0,
				    val);
	if (ret)
		return ret;

	/* Program the source MAC address into the device */
	ret = s2500_set_mac_filter(priv->ndev, priv->ndev->dev_addr);
	if (ret)
		return ret;

	val = S2500_MAC_CTRL_ADRF | S2500_MAC_CTRL_FCSA;

	return s2500_mac_ctrl_modify_bits(priv, val, false);
}

static void s2500_shutdown(struct s2500_info *priv)
{
	u32 val = S2500_MAC_CTRL_TXEN | S2500_MAC_CTRL_RXEN;
	struct net_device *ndev = priv->ndev;

	netif_stop_queue(ndev);
	phy_stop(ndev->phydev);

	s2500_mac_ctrl_modify_bits(priv, val, true);
}

static int s2500_set_promiscuous_mode(struct s2500_info *priv,
				      unsigned int rx_flags)
{
	u32 val = S2500_MAC_CTRL_ADRF;
	bool clr = false;

	if (rx_flags & IFF_PROMISC)
		clr = true;
	return s2500_mac_ctrl_modify_bits(priv, val, clr);
}

static int s2500_set_multicast_mode(struct s2500_info *priv,
				    unsigned int rx_flags,
				    struct netdev_hw_addr_list *mc)
{
	struct netdev_hw_addr *ha;
	u8 mms = OA_TC6_MAC_MMS1;
	int i, ret = 0;
	int mc_count;
	u16 addr;
	u32 val;

	mc_count = netdev_hw_addr_list_count(mc);

	if ((rx_flags & IFF_ALLMULTI) ||
	    mc_count > S2500_N_MCAST_FILTERS) {
		/* Disable multicast filter */
		ret = s2500_mac_ctrl_modify_bits(priv,
						 S2500_MAC_CTRL_MCSF,
						 true);
		if (ret)
			return ret;

		/* Accept all multicasts */
		addr = S2500_REG_MAC_ADDRMASKL(1);
		ret = oa_tc6_write_register_mms(priv->tc6, mms,
						addr, 0);
		if (ret)
			return ret;

		addr = S2500_REG_MAC_ADDRMASKH(1);
		ret = oa_tc6_write_register_mms(priv->tc6, mms,
						addr, 0x100);
		if (ret)
			return ret;

		addr = S2500_REG_MAC_ADDRFILTL(1);
		ret = oa_tc6_write_register_mms(priv->tc6, mms,
						addr, 0);
		if (ret)
			return ret;

		val = S2500_MAC_ADDRFILT_ENABLE | 0x00000100;
		addr = S2500_REG_MAC_ADDRFILTH(1);
		ret = oa_tc6_write_register_mms(priv->tc6, mms,
						addr, val);
	} else if (mc_count == 0) {
		/* Enable multicast filter */
		ret = s2500_mac_ctrl_modify_bits(priv,
						 S2500_MAC_CTRL_MCSF,
						 false);
		if (ret)
			return ret;

		/* Disable filters */
		for (i = 1; i <= S2500_N_MCAST_FILTERS; i++) {
			addr = S2500_REG_MAC_ADDRFILTH(i);
			ret = oa_tc6_write_register_mms(priv->tc6,
							mms, addr, 0);
			if (ret)
				return ret;
		}
	} else {
		u32 addrh, addrl;

		/* Disable multicast filter */
		ret = s2500_mac_ctrl_modify_bits(priv,
						 S2500_MAC_CTRL_MCSF,
						 true);
		if (ret)
			return ret;

		/* Disable filters */
		for (i = 1; i <= S2500_N_MCAST_FILTERS; i++) {
			addr = S2500_REG_MAC_ADDRFILTH(i);
			ret = oa_tc6_write_register_mms(priv->tc6,
							mms, addr, 0);
			if (ret)
				return ret;
		}

		/* Slot 0 holds the unicast MAC, multicast starts at 1 */
		i = 1;
		netdev_hw_addr_list_for_each(ha, mc) {
			const u8 *mac = ha->addr;
			int slot = i++;

			addrh = S2500_MAC_ADDRFILT_ENABLE |
				get_unaligned_be16(mac);
			addrl = get_unaligned_be32(&mac[2]);

			addr = S2500_REG_MAC_ADDRFILTH(slot);
			ret = oa_tc6_write_register_mms(priv->tc6,
							mms, addr,
							addrh);
			if (ret)
				return ret;

			addr = S2500_REG_MAC_ADDRFILTL(slot);
			ret = oa_tc6_write_register_mms(priv->tc6,
							mms, addr,
							addrl);
			if (ret)
				return ret;

			addr = S2500_REG_MAC_ADDRMASKL(slot);
			ret = oa_tc6_write_register_mms(priv->tc6,
							mms, addr,
							0xffffffff);
			if (ret)
				return ret;

			addr = S2500_REG_MAC_ADDRMASKH(slot);
			ret = oa_tc6_write_register_mms(priv->tc6,
							mms, addr,
							0xffff);
			if (ret)
				return ret;
		}
	}
	return ret;
}

static int s2500_set_rx_mode(struct net_device *ndev,
			     struct netdev_hw_addr_list *uc,
			     struct netdev_hw_addr_list *mc)
{
	struct s2500_info *priv = netdev_priv(ndev);
	int ret;

	ret = s2500_set_promiscuous_mode(priv, ndev->flags);
	if (ret)
		return ret;

	return s2500_set_multicast_mode(priv, ndev->flags, mc);
}

static int s2500_set_mac_address(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;
	int ret;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	ret = s2500_set_mac_filter(ndev, addr->sa_data);
	if (ret)
		return ret;

	eth_hw_addr_set(ndev, addr->sa_data);
	return ret;
}

static netdev_tx_t s2500_start_xmit(struct sk_buff *skb,
				    struct net_device *ndev)
{
	struct s2500_info *priv = netdev_priv(ndev);

	return oa_tc6_start_xmit(priv->tc6, skb);
}

static int s2500_open(struct net_device *ndev)
{
	struct s2500_info *priv = netdev_priv(ndev);
	u32 val;
	int ret;

	dev_dbg(&ndev->dev, "%s", "s2500_open\n");
	phy_start(priv->ndev->phydev);

	val = S2500_MAC_CTRL_TXEN | S2500_MAC_CTRL_RXEN;
	ret = s2500_mac_ctrl_modify_bits(priv, val, false);
	if (!ret)
		netif_start_queue(priv->ndev);
	else
		phy_stop(priv->ndev->phydev);
	return ret;
}

static int s2500_stop(struct net_device *ndev)
{
	struct s2500_info *priv = netdev_priv(ndev);

	dev_dbg(&ndev->dev, "%s", "s2500_stop\n");

	s2500_shutdown(priv);
	return 0;
}

static int s2500_hwtstamp_get(struct net_device *ndev,
			      struct kernel_hwtstamp_config *k_cfg)
{
	struct s2500_info *priv = netdev_priv(ndev);

	oa_tc6_hwtstamp_get(priv->tc6, k_cfg);
	return 0;
}

static int s2500_hwtstamp_set(struct net_device *ndev,
			      struct kernel_hwtstamp_config *cfg,
			      struct netlink_ext_ack *extack)
{
	struct s2500_info *priv = netdev_priv(ndev);

	return oa_tc6_hwtstamp_set(priv->tc6, cfg);
}

static const struct net_device_ops s2500_netdev_ops = {
	.ndo_open              = s2500_open,
	.ndo_stop              = s2500_stop,
	.ndo_start_xmit        = s2500_start_xmit,
	.ndo_set_mac_address   = s2500_set_mac_address,
	.ndo_set_rx_mode_async = s2500_set_rx_mode,
	.ndo_eth_ioctl         = phy_do_ioctl_running,
	.ndo_hwtstamp_get      = s2500_hwtstamp_get,
	.ndo_hwtstamp_set      = s2500_hwtstamp_set,
};

static int s2500_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct net_device *ndev;
	struct s2500_info *priv;
	u32 val;
	int ret;

	if (spi->irq < 0)
		return -ENODEV;

	ndev = devm_alloc_etherdev(dev, sizeof(struct s2500_info));
	if (!ndev)
		return -ENOMEM;

	priv = netdev_priv(ndev);
	priv->ndev = ndev;
	priv->spi = spi;
	priv->dev = dev;

	SET_NETDEV_DEV(ndev, dev);

	mutex_init(&priv->ptp_adj_lock);
	ndev->irq = spi->irq;

	/* Ensures that the first read is not from the cache. */
	priv->stats_read_at = jiffies - S2500_STATS_CACHE_PERIOD;

	spi_set_drvdata(spi, priv);

	ndev->netdev_ops = &s2500_netdev_ops;
	ndev->ethtool_ops = &s2500_ethtool_ops;
	ndev->if_port = IF_PORT_10BASET;

	priv->tc6 = oa_tc6_init(spi, ndev, NULL);
	if (IS_ERR(priv->tc6)) {
		ret = PTR_ERR(priv->tc6);
		dev_err(&spi->dev, "OA TC6 init failed\n");
		return ret;
	}
	oa_tc6_set_vend1_mms(priv->tc6, OA_TC6_PHY_C45_VS_MMS12);

	/* All read-only bits. Some are self clear. No need to write */
	ret = oa_tc6_read_register_mms(priv->tc6, OA_TC6_PHY_C45_VS_MMS12,
				       S2500_REG_VS_MIIMIRQS, &val);
	if (ret) {
		dev_err(&spi->dev, "Failed to read MIIM IRQ status\n");
		goto err_reg_read;
	}

	/* Acknowledge all IRQ status bits */
	ret = oa_tc6_read_register(priv->tc6,
				   OA_TC6_REG_STATUS0, &val);
	if (!ret) {
		/* Clear read only bit */
		val &= ~S2500_STATUS0_PHY_INT;
		oa_tc6_write_register(priv->tc6,
				      OA_TC6_REG_STATUS0, val);
	}

	ret = device_get_ethdev_address(priv->dev, ndev);
	if (ret)
		ret = s2500_read_mac_from_nvmem(priv);

	if (ret) {
		eth_hw_addr_random(ndev);
		dev_warn(&spi->dev, "Using random MAC address %pM\n",
			 ndev->dev_addr);
	}

	ret = s2500_init(priv);
	if (ret) {
		dev_err(&spi->dev, "Failure seen in s2500_init\n");
		goto err_reg_read;
	}

	/* Configure PTP as S2500 supports it */
	ret = s2500_ptp_register(priv);
	if (ret)
		goto err_reg_read;

	ret = register_netdev(ndev);
	if (!ret)
		return ret;
	dev_err(&spi->dev, "Failed to register netdev\n");
	oa_tc6_ptp_unregister(priv->tc6);
err_reg_read:
	oa_tc6_exit(priv->tc6);
	return ret;
}

static void s2500_remove(struct spi_device *spi)
{
	struct s2500_info *priv = spi_get_drvdata(spi);

	dev_dbg(&priv->ndev->dev, "%s", "s2500_remove\n");

	unregister_netdev(priv->ndev);
	oa_tc6_ptp_unregister(priv->tc6);
	oa_tc6_exit(priv->tc6);
}

static const struct of_device_id s2500_of_match[] = {
	{ .compatible = "onnn,s2500" },
	{ }
};
MODULE_DEVICE_TABLE(of, s2500_of_match);

static const struct spi_device_id s2500_ids[] = {
	{ "s2500" },
	{ }
};
MODULE_DEVICE_TABLE(spi, s2500_ids);

static struct spi_driver s2500_driver = {
	.driver = {
		.name = DRV_NAME,
		.of_match_table = s2500_of_match,
	},
	.probe = s2500_probe,
	.remove = s2500_remove,
	.id_table = s2500_ids,
};
module_spi_driver(s2500_driver);

MODULE_AUTHOR("Selva Rajagopal <selvamani.rajagopal@onsemi.com>");
MODULE_AUTHOR("Piergiorgio Beruto");
MODULE_DESCRIPTION("onsemi MACPHY ethernet driver");
MODULE_LICENSE("GPL");
