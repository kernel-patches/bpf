// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for the gigabit Ethernet PHYs integrated in the ZTE ZX279128S SoC.
 *
 * Copyright (C) 2026 Agustin Santiago Isasmendi <isasmendi.agus@gmail.com>
 *
 * The SoC has four of these PHYs, one per LAN port of its on-chip switch,
 * on the SoC's MDIO bus at addresses 10..13. There is no public datasheet:
 * the vendor-specific registers and values below are the ones the vendor's
 * own PHY initialisation uses.
 *
 * Extended registers are reached indirectly: the extended address is
 * written to register 0x10, then the data is read or written through
 * register 0x11. This is an address/data pair, not a page select (nothing
 * to read back or restore), so the phy_*_paged() helpers do not apply; the
 * pair is done with the MDIO bus lock held instead.
 */

#include <linux/bits.h>
#include <linux/module.h>
#include <linux/phy.h>

#define ZTE_GEPHY_PHY_ID		0x84b95031

#define ZTE_GEPHY_EXT_ADDR		0x10
#define ZTE_GEPHY_EXT_DATA		0x11
/* Written before the LDO is armed; the field layout is unknown. */
#define ZTE_GEPHY_LDO_CTRL		0x17
#define   ZTE_GEPHY_LDO_CTRL_VAL	0x2448

/* Extended registers */
#define ZTE_GEPHY_EXT_LDO		0xb640
#define   ZTE_GEPHY_EXT_LDO_ON		0x001f

/* Copper TX DAC drive: the vendor's full-drive ("force") pattern. Without
 * it the PHY links and receives, but does not drive the line. The
 * individual fields are not documented.
 */
static const struct {
	u16 addr;
	u16 val;
} zte_gephy_tx_dac[] = {
	{ 0xb676, 0x0003 },
	{ 0xb677, 0x0003 },
	{ 0xb667, 0x0003 },
	{ 0xb668, 0x0003 },
	{ 0xb6c2, 0x0003 },
	{ 0xb6c1, 0x0003 },
	{ 0xb678, 0x000f },
	{ 0xb669, 0x0000 },
};

static int __zte_gephy_ext_write(struct phy_device *phydev, u16 addr, u16 val)
{
	int ret;

	ret = __phy_write(phydev, ZTE_GEPHY_EXT_ADDR, addr);
	if (ret < 0)
		return ret;
	return __phy_write(phydev, ZTE_GEPHY_EXT_DATA, val);
}

static int zte_gephy_ext_read(struct phy_device *phydev, u16 addr)
{
	int ret;

	phy_lock_mdio_bus(phydev);
	ret = __phy_write(phydev, ZTE_GEPHY_EXT_ADDR, addr);
	if (ret >= 0)
		ret = __phy_read(phydev, ZTE_GEPHY_EXT_DATA);
	phy_unlock_mdio_bus(phydev);

	return ret;
}

static int zte_gephy_config_init(struct phy_device *phydev)
{
	int ret, i, ldo;

	ldo = zte_gephy_ext_read(phydev, ZTE_GEPHY_EXT_LDO);
	if (ldo < 0)
		return ldo;

	phy_lock_mdio_bus(phydev);

	/* Power the PHY's LDO, unless it already is: arming it again
	 * power-cycles the analog domain, which the switch sees as a link
	 * bounce.
	 */
	if (ldo != ZTE_GEPHY_EXT_LDO_ON) {
		phydev_dbg(phydev, "arming LDO (was %#06x)\n", ldo);
		ret = __phy_write(phydev, ZTE_GEPHY_LDO_CTRL,
				  ZTE_GEPHY_LDO_CTRL_VAL);
		if (ret >= 0)
			ret = __zte_gephy_ext_write(phydev, ZTE_GEPHY_EXT_LDO,
						    ZTE_GEPHY_EXT_LDO_ON);
		if (ret < 0)
			goto out;
	}

	for (i = 0; i < ARRAY_SIZE(zte_gephy_tx_dac); i++) {
		ret = __zte_gephy_ext_write(phydev, zte_gephy_tx_dac[i].addr,
					    zte_gephy_tx_dac[i].val);
		if (ret < 0)
			goto out;
	}
	ret = 0;
out:
	phy_unlock_mdio_bus(phydev);
	return ret;
}

static struct phy_driver zte_gephy_driver[] = {
	{
		PHY_ID_MATCH_MODEL(ZTE_GEPHY_PHY_ID),
		.name			= "ZTE ZX279128S Gigabit PHY",
		.flags			= PHY_IS_INTERNAL,
		.config_init		= zte_gephy_config_init,
		/* The boot firmware hands over with BMCR_PDOWN set. No
		 * .suspend: powering the analog domain down and up at runtime
		 * has not been tested.
		 */
		.resume			= genphy_resume,
	},
};
module_phy_driver(zte_gephy_driver);

static const struct mdio_device_id __maybe_unused zte_gephy_tbl[] = {
	{ PHY_ID_MATCH_MODEL(ZTE_GEPHY_PHY_ID) },
	{ }
};
MODULE_DEVICE_TABLE(mdio, zte_gephy_tbl);

MODULE_AUTHOR("Agustin Santiago Isasmendi <isasmendi.agus@gmail.com>");
MODULE_DESCRIPTION("ZTE ZX279128S internal Gigabit PHY driver");
MODULE_LICENSE("GPL");
