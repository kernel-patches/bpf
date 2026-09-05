// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_net.h>
#include <linux/phy.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>

#include <net/dsa.h>

#include "soce_dsa.h"
#include "soce_mdio.h"

#define SOCE_CORE_VERSION_SHIFT			24
#define SOCE_CORE_SUBVERSION_SHIFT		16
#define SOCE_LICENSED_NUM_PORTS_MASK		GENMASK(31, 27)
#define SOCE_IMPLEMENTED_NUM_PORTS_MASK		GENMASK(31, 27)
#define SOCE_IMPLEMENTED_DSA			BIT(23)
#define SOCE_DSA_REGS_BASE			0x1200
#define SOCE_TAG_ALL_FRAMES_CTRL_OFFSET		(SOCE_DSA_REGS_BASE + 0x001c)
#define SOCE_TAG_ALL_FRAMES_ENABLE		BIT(0)
#define SOCE_CUSTOM_RULES_TAGGING_OFFSET	(SOCE_DSA_REGS_BASE + 0x0020)
#define SOCE_CUSTOM_RULES_TAGGING_ENABLE	BIT(0)
#define SOCE_MIN_CORE_VERSION			0x24
#define SOCE_MIN_CORE_SUBVERSION		0x01

static void soce_phylink_get_caps(struct dsa_switch *ds, int port,
				  struct phylink_config *config)
{
	struct dsa_port *dp = dsa_to_port(ds, port);
	phy_interface_t mode;
	int ret;

	ret = of_get_phy_mode(dp->dn, &mode);
	if (ret)
		return;

	if (phy_interface_mode_is_rgmii(mode))
		phy_interface_set_rgmii(config->supported_interfaces);
	else
		__set_bit(mode, config->supported_interfaces);

	config->mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE;

	switch (mode) {
	case PHY_INTERFACE_MODE_MII:
		config->mac_capabilities |= MAC_10 | MAC_100;
		break;
	case PHY_INTERFACE_MODE_GMII:
		config->mac_capabilities |= MAC_10 | MAC_100 | MAC_1000;
		break;
	case PHY_INTERFACE_MODE_RMII:
		config->mac_capabilities |= MAC_10FD | MAC_100FD;
		break;
	default:
		if (phy_interface_mode_is_rgmii(mode))
			config->mac_capabilities |= MAC_10FD | MAC_100FD |
						    MAC_1000FD;
		break;
	}
}

static const struct soce_mdio_ops soce_mdio_ops_c22_c45 = {
	.phy_read	= soce_mdio_23_02_read,
	.phy_write	= soce_mdio_23_02_write,
	.phy_read_c45	= soce_mdio_23_02_read_c45,
	.phy_write_c45	= soce_mdio_23_02_write_c45,
};

struct soce_probe_desc {
	u32 core_version_offset;
	u32 licensed_features_offset;
	u32 implemented_features0_offset;
	u32 mdio_master_offset;
};

static const struct soce_probe_desc soce_probe_desc_swip_00_04_0c_10 = {
	.core_version_offset		= 0x0000,
	.licensed_features_offset	= 0x0004,
	.implemented_features0_offset	= 0x000c,
	.mdio_master_offset		= 0x0200,
};

static int soce_sw_validate_core_version(u8 version, u8 subversion)
{
	if (version < SOCE_MIN_CORE_VERSION ||
	    (version == SOCE_MIN_CORE_VERSION &&
	     subversion < SOCE_MIN_CORE_SUBVERSION))
		return -ENODEV;

	return 0;
}

static void soce_sw_read_core_version(struct soce_dsa_local *local,
				      const struct soce_probe_desc *probe_desc,
				      u8 *version, u8 *subversion, u16 *revision)
{
	u32 regval;

	regval = readl(local->base_addr + probe_desc->core_version_offset);
	*version = (u8)(regval >> SOCE_CORE_VERSION_SHIFT);
	*subversion = (u8)(regval >> SOCE_CORE_SUBVERSION_SHIFT);
	*revision = (u16)regval;
}

static int soce_sw_detect_features(struct soce_dsa_local *local,
				   const struct soce_probe_desc *probe_desc,
				   u32 *numports)
{
	u32 implemented_numports;
	u32 licensed_numports;
	u32 regval;

	regval = readl(local->base_addr + probe_desc->licensed_features_offset);
	licensed_numports = FIELD_GET(SOCE_LICENSED_NUM_PORTS_MASK, regval);
	if (!licensed_numports || licensed_numports > SOCE_MAX_NUM_PORTS)
		return -EINVAL;

	regval = readl(local->base_addr +
		       probe_desc->implemented_features0_offset);
	if (!(regval & SOCE_IMPLEMENTED_DSA))
		return -ENODEV;

	implemented_numports = FIELD_GET(SOCE_IMPLEMENTED_NUM_PORTS_MASK,
					 regval);
	if (!implemented_numports ||
	    implemented_numports > licensed_numports)
		return -EINVAL;

	*numports = implemented_numports;

	return 0;
}

static void soce_sw_enable_tagging(struct soce_dsa_local *local)
{
	u32 regval;

	regval = readl(local->base_addr + SOCE_TAG_ALL_FRAMES_CTRL_OFFSET);
	regval |= SOCE_TAG_ALL_FRAMES_ENABLE;
	writel(regval, local->base_addr + SOCE_TAG_ALL_FRAMES_CTRL_OFFSET);

	regval = readl(local->base_addr + SOCE_CUSTOM_RULES_TAGGING_OFFSET);
	regval |= SOCE_CUSTOM_RULES_TAGGING_ENABLE;
	writel(regval, local->base_addr + SOCE_CUSTOM_RULES_TAGGING_OFFSET);
}

static int soce_setup(struct dsa_switch *ds)
{
	struct soce_priv *priv = ds->priv;

	soce_sw_enable_tagging(&priv->local);

	return 0;
}

static enum dsa_tag_protocol soce_get_tag_protocol(struct dsa_switch *ds,
						   int port,
						   enum dsa_tag_protocol mprop)
{
	return DSA_TAG_PROTO_SDSA;
}

static const struct dsa_switch_ops soce_switch_ops = {
	.get_tag_protocol	= soce_get_tag_protocol,
	.setup			= soce_setup,
	.phylink_get_caps	= soce_phylink_get_caps,
};

static int soce_sw_probe(struct platform_device *pdev)
{
	const struct soce_probe_desc *probe_desc;
	struct device *dev = &pdev->dev;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	u8 hw_subversion;
	u16 hw_revision;
	u32 hw_numports;
	u8 hw_version;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->ds = devm_kzalloc(dev, sizeof(*priv->ds), GFP_KERNEL);
	if (!priv->ds)
		return -ENOMEM;

	priv->ds->dev = dev;
	priv->ds->priv = priv;
	probe_desc = of_device_get_match_data(dev);
	if (!probe_desc)
		return -EINVAL;

	local = &priv->local;
	mutex_init(&local->mdio_lock);

	local->base_addr = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(local->base_addr))
		return PTR_ERR(local->base_addr);

	soce_sw_read_core_version(local, probe_desc, &hw_version,
				  &hw_subversion, &hw_revision);

	ret = soce_sw_detect_features(local, probe_desc, &hw_numports);
	if (ret) {
		if (ret == -ENODEV)
			dev_err(dev, "switch core does not implement DSA\n");
		else
			dev_err(dev,
				"invalid licensed or implemented features register\n");
		return ret;
	}

	ret = soce_sw_validate_core_version(hw_version, hw_subversion);
	if (ret) {
		dev_err(dev, "unsupported switch core version %.2X.%.2X.%.4X\n",
			hw_version, hw_subversion, hw_revision);
		return ret;
	}

	priv->ds->ops = &soce_switch_ops;
	local->mdio_ops = &soce_mdio_ops_c22_c45;
	local->mdio_master_addr =
		local->base_addr + probe_desc->mdio_master_offset;

	priv->ds->num_ports = hw_numports;
	ret = soce_sw_register_mdio_buses(priv, dev, hw_numports);
	if (ret)
		return ret;

	dev_set_drvdata(dev, priv);

	ret = dsa_register_switch(priv->ds);
	if (ret)
		return ret;

	dev_info(dev,
		 "probed soce switch core version %02x.%02x.%04x with %u ports\n",
		 hw_version, hw_subversion, hw_revision, hw_numports);

	return 0;
}

static void soce_sw_remove(struct platform_device *pdev)
{
	struct soce_priv *priv = platform_get_drvdata(pdev);

	if (!priv)
		return;

	dsa_unregister_switch(priv->ds);
	platform_set_drvdata(pdev, NULL);
}

static void soce_sw_shutdown(struct platform_device *pdev)
{
	struct soce_priv *priv = platform_get_drvdata(pdev);

	if (!priv)
		return;

	dsa_switch_shutdown(priv->ds);
	platform_set_drvdata(pdev, NULL);
}

static const struct of_device_id soce_of_match[] = {
	{ .compatible = "soce,swip-00-04-0c-10",
	  .data = &soce_probe_desc_swip_00_04_0c_10 },
	{ /* sentinel */ },
};

static struct platform_driver soce_driver = {
	.probe = soce_sw_probe,
	.remove = soce_sw_remove,
	.shutdown = soce_sw_shutdown,
	.driver = {
		.name = "soce-swip",
		.of_match_table = soce_of_match,
	},
};

module_platform_driver(soce_driver);
MODULE_DEVICE_TABLE(of, soce_of_match);
MODULE_AUTHOR("Vasilij Strassheim <v.strassheim@linutronix.de>");
MODULE_DESCRIPTION("Driver for SoC-e ethernet switch family");
MODULE_LICENSE("GPL");
