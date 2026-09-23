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
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/phy.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>

#include <net/dsa.h>

#include "soce_dsa.h"

#define SOCE_MIN_NUM_PORTS			3

#define SOCE_CORE_VERSION_OFFSET		0x0000
#define SOCE_CORE_VERSION_VERSION_SHIFT		24
#define SOCE_CORE_VERSION_SUBVERSION_SHIFT	16
#define SOCE_MIN_CORE_VERSION			0x24
#define SOCE_MIN_CORE_SUBVERSION		0x01

#define SOCE_LIC_FEATURES_OFFSET		0x0004
#define SOCE_LIC_FEATURES_NUM_PORTS_MASK	GENMASK(31, 27)

#define SOCE_IMPL_FEATURES0_OFFSET		0x000c
#define SOCE_IMPL_FEATURES0_NUM_PORTS_MASK	GENMASK(31, 27)
#define SOCE_IMPL_FEATURES0_PORT_VLAN		BIT(9)
#define SOCE_IMPL_FEATURES0_DSA			BIT(23)

#define SOCE_DSA_REGS_BASE			0x1200
#define SOCE_TAG_ALL_FRAMES_CTRL_OFFSET		(SOCE_DSA_REGS_BASE + 0x001c)
#define SOCE_TAG_ALL_FRAMES_CTRL_ENABLE		BIT(0)
#define SOCE_CUSTOM_RULES_TAGGING_OFFSET	(SOCE_DSA_REGS_BASE + 0x0020)
#define SOCE_CUSTOM_RULES_TAGGING_ENABLE	BIT(0)

#define SOCE_PORTS_REGS_BASE			0x3000
#define SOCE_PORTS_SELECTOR_OFFSET		SOCE_PORTS_REGS_BASE
#define SOCE_PORTS_SELECTOR_PORT_MASK		GENMASK(7, 0)
#define SOCE_PORTS_CTRL_OFFSET			(SOCE_PORTS_REGS_BASE + 0x0004)
#define SOCE_PORTS_CTRL_INGR_EN			BIT(0)
#define SOCE_PORTS_CTRL_EGR_EN			BIT(1)

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

static int soce_sw_validate_core_version(u8 version, u8 subversion)
{
	if (version < SOCE_MIN_CORE_VERSION ||
	    (version == SOCE_MIN_CORE_VERSION &&
	     subversion < SOCE_MIN_CORE_SUBVERSION))
		return -ENODEV;

	return 0;
}

static void soce_sw_read_core_version(struct soce_dsa_local *local,
				      u8 *version, u8 *subversion,
				      u16 *revision)
{
	u32 regval;

	regval = readl(local->base_addr + SOCE_CORE_VERSION_OFFSET);
	*version = (u8)(regval >> SOCE_CORE_VERSION_VERSION_SHIFT);
	*subversion = (u8)(regval >> SOCE_CORE_VERSION_SUBVERSION_SHIFT);
	*revision = (u16)regval;
}

static int soce_sw_detect_features(struct soce_dsa_local *local,
				   u32 *numports)
{
	void __iomem *base = local->base_addr;
	u32 implemented_numports;
	u32 licensed_numports;
	u32 regval;

	regval = readl(base + SOCE_LIC_FEATURES_OFFSET);
	licensed_numports = FIELD_GET(SOCE_LIC_FEATURES_NUM_PORTS_MASK, regval);
	if (!licensed_numports || licensed_numports > SOCE_MAX_NUM_PORTS)
		return -EINVAL;

	regval = readl(base + SOCE_IMPL_FEATURES0_OFFSET);
	if (!(regval & SOCE_IMPL_FEATURES0_DSA))
		return -ENODEV;

	implemented_numports =
		FIELD_GET(SOCE_IMPL_FEATURES0_NUM_PORTS_MASK, regval);
	if (implemented_numports < SOCE_MIN_NUM_PORTS ||
	    implemented_numports > licensed_numports)
		return -EINVAL;

	*numports = implemented_numports;

	return 0;
}

static void soce_sw_enable_tagging(struct soce_dsa_local *local)
{
	void __iomem *base = local->base_addr;
	u32 regval;

	regval = readl(base + SOCE_TAG_ALL_FRAMES_CTRL_OFFSET);
	regval |= SOCE_TAG_ALL_FRAMES_CTRL_ENABLE;
	writel(regval, base + SOCE_TAG_ALL_FRAMES_CTRL_OFFSET);

	regval = readl(base + SOCE_CUSTOM_RULES_TAGGING_OFFSET);
	regval |= SOCE_CUSTOM_RULES_TAGGING_ENABLE;
	writel(regval, base + SOCE_CUSTOM_RULES_TAGGING_OFFSET);
}

static void soce_sw_disable_tagging(struct soce_dsa_local *local)
{
	void __iomem *base = local->base_addr;
	u32 regval;

	regval = readl(base + SOCE_TAG_ALL_FRAMES_CTRL_OFFSET);
	regval &= ~SOCE_TAG_ALL_FRAMES_CTRL_ENABLE;
	writel(regval, base + SOCE_TAG_ALL_FRAMES_CTRL_OFFSET);

	regval = readl(base + SOCE_CUSTOM_RULES_TAGGING_OFFSET);
	regval &= ~SOCE_CUSTOM_RULES_TAGGING_ENABLE;
	writel(regval, base + SOCE_CUSTOM_RULES_TAGGING_OFFSET);
}

static void soce_port_select(struct soce_dsa_local *local, int port)
{
	writel(FIELD_PREP(SOCE_PORTS_SELECTOR_PORT_MASK, port),
	       local->base_addr + SOCE_PORTS_SELECTOR_OFFSET);
}

static void soce_port_set_enabled(struct soce_dsa_local *local, int port,
				  bool enabled)
{
	void __iomem *base = local->base_addr;
	u32 regval;

	soce_port_select(local, port);

	regval = readl(base + SOCE_PORTS_CTRL_OFFSET);
	if (enabled)
		regval |= SOCE_PORTS_CTRL_INGR_EN | SOCE_PORTS_CTRL_EGR_EN;
	else
		regval &= ~(SOCE_PORTS_CTRL_INGR_EN | SOCE_PORTS_CTRL_EGR_EN);
	writel(regval, base + SOCE_PORTS_CTRL_OFFSET);
}

static int soce_port_enable(struct dsa_switch *ds, int port,
			    struct phy_device *phy)
{
	struct soce_priv *priv = ds->priv;

	soce_port_set_enabled(&priv->local, port, true);

	return 0;
}

static void soce_port_disable(struct dsa_switch *ds, int port)
{
	struct soce_priv *priv = ds->priv;

	soce_port_set_enabled(&priv->local, port, false);
}

static int soce_setup(struct dsa_switch *ds)
{
	struct soce_priv *priv = ds->priv;

	soce_sw_enable_tagging(&priv->local);

	return 0;
}

static void soce_teardown(struct dsa_switch *ds)
{
	struct soce_priv *priv = ds->priv;

	soce_sw_disable_tagging(&priv->local);
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
	.teardown		= soce_teardown,
	.phylink_get_caps	= soce_phylink_get_caps,
	.port_enable		= soce_port_enable,
	.port_disable		= soce_port_disable,
};

static int soce_sw_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	struct dsa_switch *ds;
	u8 hw_subversion;
	u16 hw_revision;
	u32 hw_numports;
	u8 hw_version;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ds = &priv->ds;
	ds->dev = dev;
	ds->priv = priv;

	local = &priv->local;
	local->base_addr = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(local->base_addr))
		return PTR_ERR(local->base_addr);

	soce_sw_read_core_version(local, &hw_version, &hw_subversion,
				  &hw_revision);

	ret = soce_sw_detect_features(local, &hw_numports);
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

	ds->ops = &soce_switch_ops;
	ds->num_ports = hw_numports;
	ret = devm_of_platform_populate(dev);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to populate child devices\n");

	dev_set_drvdata(dev, priv);

	ret = dsa_register_switch(ds);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to register DSA switch\n");

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

	dsa_unregister_switch(&priv->ds);
	platform_set_drvdata(pdev, NULL);
}

static void soce_sw_shutdown(struct platform_device *pdev)
{
	struct soce_priv *priv = platform_get_drvdata(pdev);

	if (!priv)
		return;

	dsa_switch_shutdown(&priv->ds);
	platform_set_drvdata(pdev, NULL);
}

static const struct of_device_id soce_of_match[] = {
	{ .compatible = "soce,swip-00-04-0c-10" },
	{ /* sentinel */ }
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
MODULE_SOFTDEP("pre: mdio-soce mdio-mux-mmioreg");
