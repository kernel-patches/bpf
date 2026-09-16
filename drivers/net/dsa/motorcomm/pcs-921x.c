// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 David Yang
 */

#include "chip.h"
#include "mdio_bus.h"
#include "pcs.h"
#include "smi.h"

#define to_device(priv) ((priv)->ds.dev)

static int
yt921x_serdes_config(struct yt921x_priv *priv, int port, unsigned int neg_mode,
		     phy_interface_t interface,
		     const unsigned long *advertising)
{
	bool inband = neg_mode & PHYLINK_PCS_NEG_INBAND;
	struct yt921x_port *pp = &priv->ports[port];
	bool changed = false;
	u16 bmcr;
	u32 mask;
	u32 ctrl;
	int adv;
	int res;

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
		ctrl = YT921X_SERDES_MODE_SGMII;
		break;
	case PHY_INTERFACE_MODE_100BASEX:
		ctrl = YT921X_SERDES_MODE_100BASEX;
		break;
	case PHY_INTERFACE_MODE_1000BASEX:
		ctrl = YT921X_SERDES_MODE_1000BASEX;
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		ctrl = YT921X_SERDES_MODE_2500BASEX;
		break;
	default:
		return -EOPNOTSUPP;
	}

	res = yt921x_reg_update_bits(priv, YT921X_SERDESn(port),
				     YT921X_SERDES_MODE_M, ctrl);
	if (res)
		return res;

	mask = YT921X_PORT_CTRL_LINK_AN | YT921X_PORT_CTRL_PAUSE_AN;
	ctrl = 0;
	if (inband)
		ctrl |= YT921X_PORT_CTRL_LINK_AN;
	if (neg_mode == PHYLINK_PCS_NEG_INBAND_ENABLED)
		ctrl |= YT921X_PORT_CTRL_PAUSE_AN;
	res = yt921x_reg_update_bits(priv, YT921X_PORTn_CTRL(port), mask, ctrl);
	if (res)
		return res;

	if (inband) {
		res = yt921x_reg_clear_bits(priv, YT921X_SERDESn(port),
					    YT921X_SERDES_LINK);
		if (res)
			return res;
	}

	adv = phylink_mii_c22_pcs_encode_advertisement(interface, advertising);
	if (adv >= 0) {
		res = yt921x_intif_modify_changed(priv, port, MII_ADVERTISE,
						  U16_MAX, adv);
		if (res < 0)
			return res;

		changed = !!res;
	}

	bmcr = neg_mode == PHYLINK_PCS_NEG_INBAND_ENABLED ? BMCR_ANENABLE : 0;
	res = yt921x_intif_modify_changed(priv, port, MII_BMCR,
					  BMCR_ANENABLE | BMCR_ISOLATE, bmcr);
	if (res < 0)
		return res;

	/* If the ANENABLE bit was changed, the PHY will restart negotiation,
	 * so we don't need to flag a change to trigger its own restart.
	 */
	if (res)
		changed = false;

	pp->inband = inband;
	return changed;
}

static unsigned int
yt921x_phylink_pcs_inband_caps(struct phylink_pcs *pcs,
			       phy_interface_t interface)
{
	return LINK_INBAND_DISABLE | LINK_INBAND_ENABLE;
}

static void
yt921x_phylink_pcs_get_state(struct phylink_pcs *pcs, unsigned int neg_mode,
			     struct phylink_link_state *state)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	struct device *dev = to_device(priv);
	int port = pp->index;
	u16 bmsr;
	u16 lpa;
	int res;

	mutex_lock(&priv->reg_lock);

	res = yt921x_intif_read(priv, port, MII_BMSR, &bmsr);
	if (res)
		goto out;

	res = yt921x_intif_read(priv, port, MII_LPA, &lpa);

out:
	mutex_unlock(&priv->reg_lock);

	if (res) {
		dev_err(dev, "Failed to %s PCS port %d: %i\n", "get state of",
			port, res);
		state->link = false;
		return;
	}

	phylink_mii_c22_pcs_decode_state(state, neg_mode, bmsr, lpa);
}

static void yt921x_phylink_pcs_an_restart(struct phylink_pcs *pcs)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	struct device *dev = to_device(priv);
	int port = pp->index;
	int res;

	mutex_lock(&priv->reg_lock);
	res = yt921x_intif_modify(priv, port, MII_BMCR, BMCR_ANRESTART,
				  BMCR_ANRESTART);
	mutex_unlock(&priv->reg_lock);

	if (res)
		dev_err(dev, "Failed to %s PCS port %d: %i\n", "restart",
			port, res);
}

static void yt921x_phylink_pcs_disable(struct phylink_pcs *pcs)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	struct device *dev = to_device(priv);
	int port = pp->index;
	int res;

	mutex_lock(&priv->reg_lock);
	res = yt921x_intif_modify(priv, port, MII_BMCR, BMCR_PDOWN,
				  BMCR_PDOWN);
	mutex_unlock(&priv->reg_lock);

	if (res)
		dev_err(dev, "Failed to %s PCS port %d: %i\n", "power down",
			port, res);
}

static int yt921x_phylink_pcs_enable(struct phylink_pcs *pcs)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	int port = pp->index;
	int res;

	mutex_lock(&priv->reg_lock);
	res = yt921x_intif_modify(priv, port, MII_BMCR,
				  BMCR_PDOWN | BMCR_ANRESTART, BMCR_ANRESTART);
	mutex_unlock(&priv->reg_lock);

	return res;
}

static int
yt921x_phylink_pcs_config(struct phylink_pcs *pcs, unsigned int neg_mode,
			  phy_interface_t interface,
			  const unsigned long *advertising,
			  bool permit_pause_to_mac)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	int port = pp->index;
	int res;

	mutex_lock(&priv->reg_lock);
	res = yt921x_serdes_config(priv, port, neg_mode, interface,
				   advertising);
	mutex_unlock(&priv->reg_lock);

	return res;
}

const struct phylink_pcs_ops yt921x_phylink_pcs_ops = {
	.pcs_inband_caps	= yt921x_phylink_pcs_inband_caps,
	.pcs_get_state		= yt921x_phylink_pcs_get_state,
	.pcs_an_restart		= yt921x_phylink_pcs_an_restart,
	.pcs_disable		= yt921x_phylink_pcs_disable,
	.pcs_enable		= yt921x_phylink_pcs_enable,
	.pcs_config		= yt921x_phylink_pcs_config,
};
