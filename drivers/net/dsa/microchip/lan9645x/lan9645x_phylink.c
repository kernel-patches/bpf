// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/phy.h>
#include <linux/phy/phy.h>

#include "lan9645x_main.h"

/* Port 4 or 7 is RGMII_0 and port 8 is RGMII_1 */
#define RGMII_IDX(port) ((port) == 8 ? 1 : 0)

void lan9645x_phylink_get_caps(struct lan9645x *lan9645x, int port,
			       struct phylink_config *c)
{
	c->mac_capabilities = MAC_ASYM_PAUSE | MAC_SYM_PAUSE | MAC_10 |
			      MAC_100 | MAC_1000FD;

	switch (port) {
	case 0 ... 3:
		__set_bit(PHY_INTERFACE_MODE_GMII, c->supported_interfaces);
		break;
	case 4:
		__set_bit(PHY_INTERFACE_MODE_GMII, c->supported_interfaces);
		phy_interface_set_rgmii(c->supported_interfaces);
		break;
	case 5 ... 6:
		/* SerDes ports: QSGMII/SGMII/1000BASEX/2500BASEX modes
		 * require PCS support which is not yet implemented.
		 * With empty supported_interfaces, these will end up being
		 * marked unused by the DSA core, if they are declared in the
		 * DT.
		 */
		break;
	case 7 ... 8:
		/* QSGMII mode on ports 7-8 requires SerDes PCS support,
		 * which is not yet implemented.
		 */
		phy_interface_set_rgmii(c->supported_interfaces);
		break;
	default:
		break;
	}
}

static void lan9645x_rgmii_set_speed(struct lan9645x *lan9645x, int port,
				     int speed)
{
	u8 tx_clk;

	tx_clk = speed == SPEED_1000 ? 1 :
		 speed == SPEED_100  ? 2 :
		 speed == SPEED_10   ? 3 : 0;

	lan_rmw(HSIO_RGMII_CFG_RGMII_RX_RST_SET(0) |
		HSIO_RGMII_CFG_RGMII_TX_RST_SET(0) |
		HSIO_RGMII_CFG_TX_CLK_CFG_SET(tx_clk),
		HSIO_RGMII_CFG_RGMII_RX_RST |
		HSIO_RGMII_CFG_RGMII_TX_RST |
		HSIO_RGMII_CFG_TX_CLK_CFG,
		lan9645x, HSIO_RGMII_CFG(RGMII_IDX(port)));
}

static void lan9645x_rgmii_dll_config(struct lan9645x_port *p)
{
	u32 rx_idx, tx_idx;

	/* DLL register layout:
	 * (N*2):   RGMII_N_RX
	 * (N*2)+1: RGMII_N_TX
	 */
	rx_idx = RGMII_IDX(p->chip_port) * 2;
	tx_idx = RGMII_IDX(p->chip_port) * 2 + 1;

	/* Enable DLL in RGMII clock paths, deassert DLL reset, and start the
	 * delay tune FSM.
	 */
	lan_rmw(HSIO_DLL_CFG_DLL_CLK_ENA_SET(1) |
		HSIO_DLL_CFG_DLL_RST_SET(0) |
		HSIO_DLL_CFG_DLL_ENA_SET(p->rx_internal_delay) |
		HSIO_DLL_CFG_DELAY_ENA_SET(p->rx_internal_delay),
		HSIO_DLL_CFG_DLL_CLK_ENA |
		HSIO_DLL_CFG_DLL_RST |
		HSIO_DLL_CFG_DLL_ENA |
		HSIO_DLL_CFG_DELAY_ENA,
		p->lan9645x, HSIO_DLL_CFG(rx_idx));

	lan_rmw(HSIO_DLL_CFG_DLL_CLK_ENA_SET(1) |
		HSIO_DLL_CFG_DLL_RST_SET(0) |
		HSIO_DLL_CFG_DLL_ENA_SET(p->tx_internal_delay) |
		HSIO_DLL_CFG_DELAY_ENA_SET(p->tx_internal_delay),
		HSIO_DLL_CFG_DLL_CLK_ENA |
		HSIO_DLL_CFG_DLL_RST |
		HSIO_DLL_CFG_DLL_ENA |
		HSIO_DLL_CFG_DELAY_ENA,
		p->lan9645x, HSIO_DLL_CFG(tx_idx));
}

static struct lan9645x_port *
lan9645x_phylink_config_to_port(struct phylink_config *config)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);

	return lan9645x_to_port(dp->ds->priv, dp->index);
}

static int lan9645x_phylink_mac_prepare(struct phylink_config *config,
					unsigned int mode,
					phy_interface_t iface)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);
	struct lan9645x *lan9645x = p->lan9645x;
	int port = p->chip_port;
	u32 hw_cfg, gmii_ena;
	bool is_rgmii;

	if (port == 5 || port == 6 || port > 8)
		return -EINVAL;

	is_rgmii = phy_interface_mode_is_rgmii(iface);

	/* RGMII_0 is a 2:1 mux shared between port 4 and port 7. Reject
	 * collisions by looking at current hardware state: the driver
	 * maintains the invariant that RGMII_0_CFG=1 iff port 4 owns
	 * RGMII_0, and for port 7 when GMII_ENA bit 7 is set this implies port
	 * 7 owns RGMII_0.
	 */
	mutex_lock(&lan9645x->port_mux_lock);

	if (is_rgmii) {
		hw_cfg = lan_rd(lan9645x, HSIO_HW_CFG);
		gmii_ena = HSIO_HW_CFG_GMII_ENA_GET(hw_cfg);

		if ((port == 4 && (gmii_ena & BIT(7))) ||
		    (port == 7 && (gmii_ena & BIT(4)) &&
		     HSIO_HW_CFG_RGMII_0_CFG_GET(hw_cfg))) {
			mutex_unlock(&lan9645x->port_mux_lock);
			return -EBUSY;
		}
	}

	lan_rmw(HSIO_HW_CFG_GMII_ENA_SET(BIT(port)),
		HSIO_HW_CFG_GMII_ENA_SET(BIT(port)), lan9645x, HSIO_HW_CFG);

	if (port == 4) {
		lan_rmw(HSIO_HW_CFG_RGMII_0_CFG_SET(is_rgmii),
			HSIO_HW_CFG_RGMII_0_CFG,
			lan9645x, HSIO_HW_CFG);
	} else if (port == 7 && is_rgmii) {
		lan_rmw(HSIO_HW_CFG_RGMII_0_CFG_SET(0),
			HSIO_HW_CFG_RGMII_0_CFG,
			lan9645x, HSIO_HW_CFG);
	}

	mutex_unlock(&lan9645x->port_mux_lock);

	return 0;
}

static void lan9645x_phylink_mac_config(struct phylink_config *config,
					unsigned int mode,
					const struct phylink_link_state *state)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);

	if (phy_interface_mode_is_rgmii(state->interface))
		lan9645x_rgmii_dll_config(p);
}

static bool lan9645x_port_is_cuphy(struct lan9645x *lan9645x, int port,
				   phy_interface_t interface)
{
	return port >= 0 && port <= 4 && interface == PHY_INTERFACE_MODE_GMII;
}

void lan9645x_phylink_port_down(struct lan9645x *lan9645x, int port)
{
	struct lan9645x_port *p = lan9645x_to_port(lan9645x, port);
	u32 val;

	/* Disable MAC frame reception */
	lan_rmw(DEV_MAC_ENA_CFG_RX_ENA_SET(0),
		DEV_MAC_ENA_CFG_RX_ENA,
		lan9645x, DEV_MAC_ENA_CFG(p->chip_port));

	/* Disable traffic being sent to or from switch port */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(0),
		QSYS_SW_PORT_MODE_PORT_ENA,
		lan9645x, QSYS_SW_PORT_MODE(p->chip_port));

	/* Disable dequeuing from the egress queues  */
	lan_rmw(QSYS_PORT_MODE_DEQUEUE_DIS_SET(1),
		QSYS_PORT_MODE_DEQUEUE_DIS,
		lan9645x, QSYS_PORT_MODE(p->chip_port));

	/* Disable Flowcontrol */
	lan_rmw(SYS_PAUSE_CFG_PAUSE_ENA_SET(0),
		SYS_PAUSE_CFG_PAUSE_ENA,
		lan9645x, SYS_PAUSE_CFG(p->chip_port));

	/* Wait a worst case time 8ms (10K jumbo/10Mbit) */
	usleep_range(8 * USEC_PER_MSEC, 9 * USEC_PER_MSEC);

	/* Disable HDX backpressure. */
	lan_rmw(SYS_FRONT_PORT_MODE_HDX_MODE_SET(0),
		SYS_FRONT_PORT_MODE_HDX_MODE,
		lan9645x, SYS_FRONT_PORT_MODE(p->chip_port));

	/* Flush the queues associated with the port */
	lan_rmw(QSYS_SW_PORT_MODE_AGING_MODE_SET(3),
		QSYS_SW_PORT_MODE_AGING_MODE,
		lan9645x, QSYS_SW_PORT_MODE(p->chip_port));

	/* Enable dequeuing from the egress queues */
	lan_rmw(QSYS_PORT_MODE_DEQUEUE_DIS_SET(0),
		QSYS_PORT_MODE_DEQUEUE_DIS,
		lan9645x, QSYS_PORT_MODE(p->chip_port));

	/* Wait until flushing is complete */
	if (lan9645x_rd_poll_slow(lan9645x, QSYS_SW_STATUS(p->chip_port),
				  val, !QSYS_SW_STATUS_EQ_AVAIL_GET(val)))
		dev_err(lan9645x->dev, "Flush timeout chip port %u\n", port);

	/* Disable MAC tx */
	lan_rmw(DEV_MAC_ENA_CFG_TX_ENA_SET(0),
		DEV_MAC_ENA_CFG_TX_ENA,
		lan9645x, DEV_MAC_ENA_CFG(p->chip_port));

	/* Reset the Port and MAC clock domains */
	lan_rmw(DEV_CLOCK_CFG_PORT_RST_SET(1),
		DEV_CLOCK_CFG_PORT_RST,
		lan9645x, DEV_CLOCK_CFG(p->chip_port));

	/* Wait before resetting MAC clock domains. */
	usleep_range(USEC_PER_MSEC, 2 * USEC_PER_MSEC);

	lan_rmw(DEV_CLOCK_CFG_MAC_TX_RST_SET(1) |
		DEV_CLOCK_CFG_MAC_RX_RST_SET(1) |
		DEV_CLOCK_CFG_PORT_RST_SET(1),
		DEV_CLOCK_CFG_MAC_TX_RST |
		DEV_CLOCK_CFG_MAC_RX_RST |
		DEV_CLOCK_CFG_PORT_RST,
		lan9645x, DEV_CLOCK_CFG(p->chip_port));

	/* Clear flushing */
	lan_rmw(QSYS_SW_PORT_MODE_AGING_MODE_SET(1),
		QSYS_SW_PORT_MODE_AGING_MODE,
		lan9645x, QSYS_SW_PORT_MODE(p->chip_port));
}

static void lan9645x_phylink_mac_link_down(struct phylink_config *config,
					   unsigned int link_an_mode,
					   phy_interface_t interface)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);
	struct lan9645x *lan9645x = p->lan9645x;

	lan9645x_phylink_port_down(lan9645x, p->chip_port);
}

static void lan9645x_phylink_mac_link_up(struct phylink_config *config,
					 struct phy_device *phydev,
					 unsigned int link_an_mode,
					 phy_interface_t interface, int speed,
					 int duplex, bool tx_pause,
					 bool rx_pause)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);
	int rx_ifg1, rx_ifg2, tx_ifg, gtx_clk = 0;
	struct lan9645x *lan9645x = p->lan9645x;
	int gspeed = LAN9645X_SPEED_DISABLED;
	int port = p->chip_port;
	int mode = 0;
	int fc_spd;

	/* Configure RGMII TX clock for the negotiated speed */
	if (phy_interface_mode_is_rgmii(interface))
		lan9645x_rgmii_set_speed(lan9645x, port, speed);

	if (duplex == DUPLEX_FULL) {
		mode |= DEV_MAC_MODE_CFG_FDX_ENA_SET(1);
		tx_ifg = 0x5;
		rx_ifg2 = 0x2;

	} else {
		tx_ifg = 0x6;
		rx_ifg2 = 0x2;
	}

	switch (speed) {
	case SPEED_10:
		rx_ifg1 = 0x2;
		gspeed = LAN9645X_SPEED_10;
		break;
	case SPEED_100:
		rx_ifg1 = 0x1;
		gspeed = LAN9645X_SPEED_100;
		break;
	case SPEED_1000:
		gspeed = LAN9645X_SPEED_1000;
		mode |= DEV_MAC_MODE_CFG_GIGA_MODE_ENA_SET(1);
		mode |= DEV_MAC_MODE_CFG_FDX_ENA_SET(1);
		tx_ifg = 0x6;
		rx_ifg1 = 0x1;
		rx_ifg2 = 0x2;
		gtx_clk = 1;
		break;
	case SPEED_2500:
		gspeed = LAN9645X_SPEED_2500;
		mode |= DEV_MAC_MODE_CFG_GIGA_MODE_ENA_SET(1);
		mode |= DEV_MAC_MODE_CFG_FDX_ENA_SET(1);
		tx_ifg = 0x6;
		rx_ifg1 = 0x1;
		rx_ifg2 = 0x2;
		break;
	default:
		dev_err(lan9645x->dev, "Unsupported speed on port %d: %d\n",
			p->chip_port, speed);
		return;
	}

	fc_spd = lan9645x_speed_fc_enc(gspeed);

	lan_rmw(mode,
		DEV_MAC_MODE_CFG_FDX_ENA |
		DEV_MAC_MODE_CFG_GIGA_MODE_ENA,
		lan9645x, DEV_MAC_MODE_CFG(p->chip_port));

	lan_rmw(DEV_MAC_IFG_CFG_TX_IFG_SET(tx_ifg) |
		DEV_MAC_IFG_CFG_RX_IFG1_SET(rx_ifg1) |
		DEV_MAC_IFG_CFG_RX_IFG2_SET(rx_ifg2),
		DEV_MAC_IFG_CFG_TX_IFG |
		DEV_MAC_IFG_CFG_RX_IFG1 |
		DEV_MAC_IFG_CFG_RX_IFG2,
		lan9645x, DEV_MAC_IFG_CFG(p->chip_port));

	if (lan9645x_port_is_cuphy(lan9645x, port, interface)) {
		lan_rmw(CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA_SET(gtx_clk),
			CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA, lan9645x,
			CHIP_TOP_CUPHY_PORT_CFG(p->chip_port));
	}

	lan_rmw(SYS_PAUSE_CFG_PAUSE_ENA_SET(1),
		SYS_PAUSE_CFG_PAUSE_ENA,
		lan9645x, SYS_PAUSE_CFG(p->chip_port));

	/* Flow control */
	lan_rmw(SYS_MAC_FC_CFG_FC_LINK_SPEED_SET(fc_spd) |
		SYS_MAC_FC_CFG_FC_LATENCY_CFG_SET(0x7) |
		SYS_MAC_FC_CFG_ZERO_PAUSE_ENA_SET(1) |
		SYS_MAC_FC_CFG_PAUSE_VAL_CFG_SET(0xffff) |
		SYS_MAC_FC_CFG_RX_FC_ENA_SET(rx_pause ? 1 : 0) |
		SYS_MAC_FC_CFG_TX_FC_ENA_SET(tx_pause ? 1 : 0),
		SYS_MAC_FC_CFG_FC_LINK_SPEED |
		SYS_MAC_FC_CFG_FC_LATENCY_CFG |
		SYS_MAC_FC_CFG_ZERO_PAUSE_ENA |
		SYS_MAC_FC_CFG_PAUSE_VAL_CFG |
		SYS_MAC_FC_CFG_RX_FC_ENA |
		SYS_MAC_FC_CFG_TX_FC_ENA,
		lan9645x, SYS_MAC_FC_CFG(p->chip_port));

	/* Enable MAC module */
	lan_wr(DEV_MAC_ENA_CFG_RX_ENA_SET(1) |
	       DEV_MAC_ENA_CFG_TX_ENA_SET(1),
	       lan9645x, DEV_MAC_ENA_CFG(p->chip_port));

	/* port _must_ be taken out of reset before MAC. */
	lan_rmw(DEV_CLOCK_CFG_PORT_RST_SET(0),
		DEV_CLOCK_CFG_PORT_RST,
		lan9645x, DEV_CLOCK_CFG(p->chip_port));

	/* Take out the clock from reset. Note this write will set all these
	 * fields to zero:
	 *
	 * DEV_CLOCK_CFG[*].MAC_TX_RST
	 * DEV_CLOCK_CFG[*].MAC_RX_RST
	 * DEV_CLOCK_CFG[*].PCS_TX_RST
	 * DEV_CLOCK_CFG[*].PCS_RX_RST
	 * DEV_CLOCK_CFG[*].PORT_RST
	 * DEV_CLOCK_CFG[*].PHY_RST
	 *
	 * Note link_down will assert PORT_RST, MAC_RX_RST and MAC_TX_RST, so
	 * we are effectively taking the mac tx/rx clocks out of reset.
	 *
	 * This linkspeed field has a slightly different encoding from others:
	 *
	 * - 0 is no-link
	 * - 1 is both 2500/1000
	 * - 2 is 100mbit
	 * - 3 is 10mbit
	 *
	 */
	lan_wr(DEV_CLOCK_CFG_LINK_SPEED_SET(fc_spd == 0 ? 1 : fc_spd),
	       lan9645x,
	       DEV_CLOCK_CFG(p->chip_port));

	/* Core: Enable port for frame transfer */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(1) |
		QSYS_SW_PORT_MODE_SCH_NEXT_CFG_SET(1) |
		QSYS_SW_PORT_MODE_INGRESS_DROP_MODE_SET(1) |
		QSYS_SW_PORT_MODE_TX_PFC_ENA_SET(0),
		QSYS_SW_PORT_MODE_PORT_ENA |
		QSYS_SW_PORT_MODE_SCH_NEXT_CFG |
		QSYS_SW_PORT_MODE_INGRESS_DROP_MODE |
		QSYS_SW_PORT_MODE_TX_PFC_ENA,
		lan9645x, QSYS_SW_PORT_MODE(p->chip_port));
}

const struct phylink_mac_ops lan9645x_phylink_mac_ops = {
	.mac_prepare			= lan9645x_phylink_mac_prepare,
	.mac_config			= lan9645x_phylink_mac_config,
	.mac_link_down			= lan9645x_phylink_mac_link_down,
	.mac_link_up			= lan9645x_phylink_mac_link_up,
};
