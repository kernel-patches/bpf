// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/io.h>
#include <linux/iopoll.h>
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

#define SOCE_VLAN_REGS_BASE			0x0d00
#define SOCE_VLAN_CTRL_OFFSET			SOCE_VLAN_REGS_BASE
#define SOCE_VLAN_CTRL_ENABLE			BIT(0)
#define SOCE_VLAN_RESET_OFFSET			(SOCE_VLAN_REGS_BASE + 0x0004)
#define SOCE_VLAN_RESET_CMD			BIT(0)
#define SOCE_VLAN_PORT_SEL_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0010)
#define SOCE_VLAN_PORT_SEL_PORT_MASK		GENMASK(7, 0)
#define SOCE_VLAN_PORT_MODE_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0014)
#define SOCE_VLAN_PORT_MODE_HYBRID		0x2
#define SOCE_VLAN_PORT_TYPE_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0018)
#define SOCE_VLAN_PORT_TYPE_UNAWARE		0x0
#define SOCE_VLAN_PORT_TYPE_C_PORT		0x1
#define SOCE_VLAN_PORT_VLAN_OFFSET		(SOCE_VLAN_REGS_BASE + 0x001c)
#define SOCE_VLAN_PORT_VLAN_PVID_MASK		GENMASK(11, 0)
#define SOCE_VLAN_PORT_INGR_FILTER_OFFSET	(SOCE_VLAN_REGS_BASE + 0x0020)
#define SOCE_VLAN_PORT_INGR_FILTER_EN		BIT(0)
#define SOCE_VLAN_PORT_INGR_ACCEPT_OFFSET	(SOCE_VLAN_REGS_BASE + 0x0024)
#define SOCE_VLAN_PORT_INGR_ACCEPT_ALL		0x0
#define SOCE_VLAN_PORT_INGR_ACCEPT_TAGGED_ONLY	0x1
#define SOCE_VLAN_PORT_EGR_TAG_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0028)
#define SOCE_VLAN_PORT_EGR_TAG_MASK		GENMASK(1, 0)
#define SOCE_VLAN_PORT_EGR_TAG_UNTAG_PORT	0x0
#define SOCE_VLAN_PORT_EGR_TAG_CUSTOM_UNTAG	0x3
#define SOCE_VLAN_VID_SEL_OFFSET		(SOCE_VLAN_REGS_BASE + 0x002c)
#define SOCE_VLAN_VID_SEL_VID_MASK		GENMASK(11, 0)
#define SOCE_VLAN_MEMBER_CTRL_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0030)
#define SOCE_VLAN_MEMBER_CTRL_WRITE		BIT(0)
#define SOCE_VLAN_MEMBER_PORTS_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0034)
#define SOCE_VLAN_UNTAG_CTRL_OFFSET		(SOCE_VLAN_REGS_BASE + 0x003c)
#define SOCE_VLAN_UNTAG_CTRL_WRITE		BIT(0)
#define SOCE_VLAN_UNTAG_PORTS_OFFSET		(SOCE_VLAN_REGS_BASE + 0x0040)
#define SOCE_VLAN_CMD_TIMEOUT_US		1000

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
				   struct soce_features *features)
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

	features->port_vlan = regval & SOCE_IMPL_FEATURES0_PORT_VLAN;

	implemented_numports =
		FIELD_GET(SOCE_IMPL_FEATURES0_NUM_PORTS_MASK, regval);
	if (implemented_numports < SOCE_MIN_NUM_PORTS ||
	    implemented_numports > licensed_numports)
		return -EINVAL;

	features->num_ports = implemented_numports;

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

static void soce_vlan_set_enabled(struct soce_dsa_local *local, bool enabled)
{
	void __iomem *base = local->base_addr;
	u32 regval;

	regval = readl(base + SOCE_VLAN_CTRL_OFFSET);
	if (enabled)
		regval |= SOCE_VLAN_CTRL_ENABLE;
	else
		regval &= ~SOCE_VLAN_CTRL_ENABLE;
	writel(regval, base + SOCE_VLAN_CTRL_OFFSET);
}

static int soce_vlan_reset(struct soce_dsa_local *local)
{
	void __iomem *base = local->base_addr;
	u32 regval;

	writel(SOCE_VLAN_RESET_CMD, base + SOCE_VLAN_RESET_OFFSET);

	return readl_poll_timeout(base + SOCE_VLAN_RESET_OFFSET,
				  regval, !(regval & SOCE_VLAN_RESET_CMD), 10,
				  SOCE_VLAN_CMD_TIMEOUT_US);
}

static int soce_vlan_wait_for_write(struct soce_dsa_local *local, u32 offset,
				    u32 mask)
{
	void __iomem *base = local->base_addr;
	u32 regval;

	return readl_poll_timeout(base + offset, regval,
				  !(regval & mask), 10,
				  SOCE_VLAN_CMD_TIMEOUT_US);
}

static void soce_vlan_select_port(struct soce_dsa_local *local, int port)
{
	writel(FIELD_PREP(SOCE_VLAN_PORT_SEL_PORT_MASK, port),
	       local->base_addr + SOCE_VLAN_PORT_SEL_OFFSET);
}

static void soce_vlan_select_vid(struct soce_dsa_local *local, u16 vid)
{
	writel(FIELD_PREP(SOCE_VLAN_VID_SEL_VID_MASK, vid),
	       local->base_addr + SOCE_VLAN_VID_SEL_OFFSET);
}

static void soce_vlan_config_port(struct soce_priv *priv, int port,
				  bool vlan_filtering)
{
	struct soce_dsa_local *local = &priv->local;
	void __iomem *base = local->base_addr;
	u32 egress_tagging;
	u32 port_type;
	u32 regval;
	u32 accept;

	port_type = vlan_filtering ? SOCE_VLAN_PORT_TYPE_C_PORT :
				     SOCE_VLAN_PORT_TYPE_UNAWARE;
	egress_tagging = vlan_filtering ? SOCE_VLAN_PORT_EGR_TAG_CUSTOM_UNTAG :
					   SOCE_VLAN_PORT_EGR_TAG_UNTAG_PORT;

	soce_vlan_select_port(local, port);
	writel(SOCE_VLAN_PORT_MODE_HYBRID, base + SOCE_VLAN_PORT_MODE_OFFSET);
	writel(port_type, base + SOCE_VLAN_PORT_TYPE_OFFSET);
	writel(FIELD_PREP(SOCE_VLAN_PORT_VLAN_PVID_MASK,
			  priv->port_pvid[port]),
	       base + SOCE_VLAN_PORT_VLAN_OFFSET);
	writel(vlan_filtering ? SOCE_VLAN_PORT_INGR_FILTER_EN : 0,
	       base + SOCE_VLAN_PORT_INGR_FILTER_OFFSET);

	/* Without a PVID, untagged frames have no VLAN to be classified
	 * into, so only accept tagged frames while filtering.
	 */
	accept = vlan_filtering && !priv->port_pvid[port] ?
			 SOCE_VLAN_PORT_INGR_ACCEPT_TAGGED_ONLY :
			 SOCE_VLAN_PORT_INGR_ACCEPT_ALL;
	writel(accept, base + SOCE_VLAN_PORT_INGR_ACCEPT_OFFSET);

	regval = readl(base + SOCE_VLAN_PORT_EGR_TAG_OFFSET);
	regval &= ~SOCE_VLAN_PORT_EGR_TAG_MASK;
	regval |= FIELD_PREP(SOCE_VLAN_PORT_EGR_TAG_MASK, egress_tagging);
	writel(regval, base + SOCE_VLAN_PORT_EGR_TAG_OFFSET);
}

static int soce_vlan_write_entry(struct soce_priv *priv, u16 vid)
{
	struct soce_dsa_local *local = &priv->local;
	void __iomem *base = local->base_addr;
	u32 cpu_ports;
	u32 untagged;
	u32 members;
	int ret;

	/* The CPU port must be a tagged member of every active VLAN so
	 * tagged frames can reach the conduit.
	 */
	cpu_ports = dsa_cpu_ports(&priv->ds);
	members = priv->vlan_members[vid];
	if (members)
		members |= cpu_ports;
	untagged = priv->vlan_untagged[vid] & ~cpu_ports;

	soce_vlan_select_vid(local, vid);
	writel(members, base + SOCE_VLAN_MEMBER_PORTS_OFFSET);
	writel(SOCE_VLAN_MEMBER_CTRL_WRITE,
	       base + SOCE_VLAN_MEMBER_CTRL_OFFSET);
	ret = soce_vlan_wait_for_write(local, SOCE_VLAN_MEMBER_CTRL_OFFSET,
				       SOCE_VLAN_MEMBER_CTRL_WRITE);
	if (ret)
		return ret;

	writel(untagged, base + SOCE_VLAN_UNTAG_PORTS_OFFSET);
	writel(SOCE_VLAN_UNTAG_CTRL_WRITE,
	       base + SOCE_VLAN_UNTAG_CTRL_OFFSET);

	return soce_vlan_wait_for_write(local, SOCE_VLAN_UNTAG_CTRL_OFFSET,
					SOCE_VLAN_UNTAG_CTRL_WRITE);
}

static int soce_vlan_setup(struct dsa_switch *ds)
{
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;
	struct dsa_port *dp;
	int ret;

	local = &priv->local;

	if (!priv->features.port_vlan)
		return 0;

	ret = soce_vlan_reset(local);
	if (ret) {
		dev_err(ds->dev, "failed to reset VLAN configuration: %d\n",
			ret);
		return ret;
	}

	/* Default every port to PVID 1, unfiltered, so standalone
	 * forwarding keeps working before any bridge VLAN is configured.
	 */
	scoped_guard(mutex, &priv->vlan_lock) {
		dsa_switch_for_each_available_port(dp, ds) {
			priv->port_pvid[dp->index] = 1;
			soce_vlan_config_port(priv, dp->index, false);
		}
		soce_vlan_set_enabled(local, true);
	}

	return 0;
}

static void soce_vlan_teardown(struct soce_priv *priv)
{
	struct soce_dsa_local *local = &priv->local;
	int ret;

	if (!priv->features.port_vlan)
		return;

	scoped_guard(mutex, &priv->vlan_lock) {
		ret = soce_vlan_reset(local);
		if (ret)
			dev_warn(priv->ds.dev,
				 "failed to reset VLAN configuration during teardown: %d\n",
				 ret);
		soce_vlan_set_enabled(local, false);
	}
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
	int ret;

	ret = soce_vlan_setup(ds);
	if (ret)
		return ret;

	soce_sw_enable_tagging(&priv->local);

	return 0;
}

static void soce_teardown(struct dsa_switch *ds)
{
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;

	local = &priv->local;

	soce_sw_disable_tagging(local);
	soce_vlan_teardown(priv);
}

static enum dsa_tag_protocol soce_get_tag_protocol(struct dsa_switch *ds,
						   int port,
						   enum dsa_tag_protocol mprop)
{
	return DSA_TAG_PROTO_SDSA;
}

static int soce_port_vlan_add(struct dsa_switch *ds, int port,
			      const struct switchdev_obj_port_vlan *vlan,
			      struct netlink_ext_ack *extack)
{
	struct dsa_port *dp = dsa_to_port(ds, port);
	struct soce_priv *priv = ds->priv;
	u32 port_mask = BIT(port);
	u32 *untagged_ports;
	u32 old_untagged;
	u32 old_members;
	bool untagged;
	u32 *members;
	int ret;

	untagged_ports = priv->vlan_untagged;
	members = priv->vlan_members;

	if (!priv->features.port_vlan) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Port VLAN support is not implemented in the switch core");
		return -EOPNOTSUPP;
	}

	if (!vlan->vid)
		return 0;

	untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;

	scoped_guard(mutex, &priv->vlan_lock) {
		old_members = members[vlan->vid];
		old_untagged = untagged_ports[vlan->vid];

		members[vlan->vid] |= port_mask;
		if (untagged)
			untagged_ports[vlan->vid] |= port_mask;
		else
			untagged_ports[vlan->vid] &= ~port_mask;

		ret = soce_vlan_write_entry(priv, vlan->vid);
		if (ret) {
			NL_SET_ERR_MSG_MOD(extack,
					   "failed to update VLAN hardware tables");
			dev_err(ds->dev,
				"failed to add VLAN %u on port %d: %d\n",
				vlan->vid, port, ret);
			members[vlan->vid] = old_members;
			untagged_ports[vlan->vid] = old_untagged;
			return ret;
		}

		if (vlan->flags & BRIDGE_VLAN_INFO_PVID) {
			priv->port_pvid[port] = vlan->vid;
			soce_vlan_config_port(priv, port,
					      dsa_port_is_vlan_filtering(dp));
		}
	}

	return ret;
}

static int soce_port_vlan_del(struct dsa_switch *ds, int port,
			      const struct switchdev_obj_port_vlan *vlan)
{
	struct dsa_port *dp = dsa_to_port(ds, port);
	struct soce_priv *priv = ds->priv;
	u32 port_mask = BIT(port);
	u32 *untagged_ports;
	u32 old_untagged;
	u32 old_members;
	u32 *members;
	int ret;

	untagged_ports = priv->vlan_untagged;
	members = priv->vlan_members;

	if (!priv->features.port_vlan)
		return -EOPNOTSUPP;

	if (!vlan->vid)
		return 0;

	scoped_guard(mutex, &priv->vlan_lock) {
		old_members = members[vlan->vid];
		old_untagged = untagged_ports[vlan->vid];
		members[vlan->vid] &= ~port_mask;
		untagged_ports[vlan->vid] &= ~port_mask;
		ret = soce_vlan_write_entry(priv, vlan->vid);
		if (ret) {
			dev_err(ds->dev,
				"failed to delete VLAN %u from port %d: %d\n",
				vlan->vid, port, ret);
			members[vlan->vid] = old_members;
			untagged_ports[vlan->vid] = old_untagged;
			return ret;
		}

		if (priv->port_pvid[port] == vlan->vid) {
			priv->port_pvid[port] = 0;
			soce_vlan_config_port(priv, port,
					      dsa_port_is_vlan_filtering(dp));
		}
	}

	return ret;
}

static int soce_port_vlan_filtering(struct dsa_switch *ds, int port,
				    bool vlan_filtering,
				    struct netlink_ext_ack *extack)
{
	struct soce_priv *priv = ds->priv;

	if (!priv->features.port_vlan) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Port VLAN support is not implemented in the switch core");
		return -EOPNOTSUPP;
	}

	scoped_guard(mutex, &priv->vlan_lock)
		soce_vlan_config_port(priv, port, vlan_filtering);

	return 0;
}

static const struct dsa_switch_ops soce_switch_ops = {
	.get_tag_protocol	= soce_get_tag_protocol,
	.setup			= soce_setup,
	.teardown		= soce_teardown,
	.phylink_get_caps	= soce_phylink_get_caps,
	.port_enable		= soce_port_enable,
	.port_disable		= soce_port_disable,
	.port_vlan_filtering	= soce_port_vlan_filtering,
	.port_vlan_add		= soce_port_vlan_add,
	.port_vlan_del		= soce_port_vlan_del,
};

static int soce_sw_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	struct dsa_switch *ds;
	u8 hw_subversion;
	u16 hw_revision;
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

	ret = soce_sw_detect_features(local, &priv->features);
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

	if (priv->features.port_vlan) {
		ret = devm_mutex_init(dev, &priv->vlan_lock);
		if (ret)
			return ret;

		priv->vlan_members =
			devm_kcalloc(dev, VLAN_N_VID,
				     sizeof(*priv->vlan_members), GFP_KERNEL);
		if (!priv->vlan_members)
			return -ENOMEM;

		priv->vlan_untagged =
			devm_kcalloc(dev, VLAN_N_VID,
				     sizeof(*priv->vlan_untagged), GFP_KERNEL);
		if (!priv->vlan_untagged)
			return -ENOMEM;
	} else {
		dev_warn(dev,
			 "VLAN-tagged frames received on the CPU port are unsupported\n");
	}

	ds->ops = &soce_switch_ops;
	ds->num_ports = priv->features.num_ports;

	/* Force VLAN uppers always through the callbacks, so cores without
	 * Port VLAN feature can reject them instead of silently dropping
	 * VLAN frames.
	 */
	ds->needs_standalone_vlan_filtering = true;
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
		 hw_version, hw_subversion, hw_revision,
		 priv->features.num_ports);

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
