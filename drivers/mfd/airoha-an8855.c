// SPDX-License-Identifier: GPL-2.0+
/*
 * Core driver for Airoha AN8855 Switch
 *
 * Copyright (C) 2024 Christian Marangi <ansuelsmth@gmail.com>
 */

#include <linux/bitfield.h>
#include <linux/fwnode_mdio.h>
#include <linux/gpio/consumer.h>
#include <linux/mfd/core.h>
#include <linux/mdio.h>
#include <linux/mdio/mdio-regmap.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy.h>
#include <linux/regmap.h>

/* Register for HW trap status */
#define AN8855_HWTRAP			0x1000009c

/*
 * Register of the Switch ID
 * (called Project ID in Documentation)
 */
#define AN8855_CREV			0x10005000
#define   AN8855_ID			0x8855 /* Switch ID */

/* Register for GPHY Power Down
 * Used to Toggle the Gigabit PHY power and enable them.
 */
#define AN8855_RG_GPHY_AFE_PWD		0x1028c840

/* MII Registers */
#define AN8855_PHY_SELECT_PAGE		0x1f
#define   AN8855_PHY_PAGE		GENMASK(2, 0)
#define   AN8855_PHY_PAGE_STANDARD	FIELD_PREP_CONST(AN8855_PHY_PAGE, 0x0)
#define   AN8855_PHY_PAGE_EXTENDED_1	FIELD_PREP_CONST(AN8855_PHY_PAGE, 0x1)
#define   AN8855_PHY_PAGE_EXTENDED_4	FIELD_PREP_CONST(AN8855_PHY_PAGE, 0x4)

/* MII Registers Page 4 */
#define AN8855_PBUS_MODE		0x10
#define   AN8855_PBUS_MODE_ADDR_FIXED	0x0
#define   AN8855_PBUS_MODE_ADDR_INCR	BIT(15)
#define AN8855_PBUS_WR_ADDR_HIGH	0x11
#define AN8855_PBUS_WR_ADDR_LOW		0x12
#define AN8855_PBUS_WR_DATA_HIGH	0x13
#define AN8855_PBUS_WR_DATA_LOW		0x14
#define AN8855_PBUS_RD_ADDR_HIGH	0x15
#define AN8855_PBUS_RD_ADDR_LOW		0x16
#define AN8855_PBUS_RD_DATA_HIGH	0x17
#define AN8855_PBUS_RD_DATA_LOW		0x18

#define AN8855_MAX_PHY_PORT		5

struct an8855_core {
	struct mii_bus *bus;
	struct mii_bus *phy_bus;
	unsigned int switch_addr;
	u16 current_page;
};

struct an8855_phy {
	u8 addr;
	struct an8855_core *core;
};

struct an8855_phy_bus {
	struct mii_bus *bus;
	struct fwnode_handle *node;
	u8 addr;
};

static const struct mfd_cell an8855_cells[] = {
	MFD_CELL_OF("an8855-efuse", NULL, NULL, 0, 0,
		    "airoha,an8855-efuse"),
	MFD_CELL_OF("an8855-switch", NULL, NULL, 0, 0,
		    "airoha,an8855-switch"),
};

static int an8855_mii_set_page(struct an8855_core *priv, u8 addr,
			       u8 page) __must_hold(&priv->bus->mdio_lock)
{
	struct mii_bus *bus = priv->bus;
	int ret;

	ret = __mdiobus_write(bus, addr, AN8855_PHY_SELECT_PAGE, page);
	if (ret) {
		dev_err_ratelimited(&bus->dev, "failed to set mii page\n");
		return ret;
	}

	/* Cache current page if next MII read/write is for Switch page */
	priv->current_page = page;
	return 0;
}

static int an8855_mii_read32(struct mii_bus *bus, u8 phy_id, u32 reg,
			     u32 *val) __must_hold(&bus->mdio_lock)
{
	int lo, hi, ret;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_MODE,
			      AN8855_PBUS_MODE_ADDR_FIXED);
	if (ret)
		goto err;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_RD_ADDR_HIGH,
			      upper_16_bits(reg));
	if (ret)
		goto err;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_RD_ADDR_LOW,
			      lower_16_bits(reg));
	if (ret)
		goto err;

	hi = __mdiobus_read(bus, phy_id, AN8855_PBUS_RD_DATA_HIGH);
	if (hi < 0) {
		ret = hi;
		goto err;
	}

	lo = __mdiobus_read(bus, phy_id, AN8855_PBUS_RD_DATA_LOW);
	if (lo < 0) {
		ret = lo;
		goto err;
	}

	*val = ((u32)hi << 16) | lo;

	return 0;
err:
	dev_err_ratelimited(&bus->dev, "failed to read register\n");
	return ret;
}

/*
 * Protect concurrent access to phy page if switch address also
 * expose a PHY.
 */
static void an8855_regmap_lock(struct an8855_core *priv)
{
	if (priv->phy_bus)
		mutex_lock(&priv->phy_bus->mdio_lock);
	mutex_lock_nested(&priv->bus->mdio_lock, MDIO_MUTEX_NESTED);
}

static void an8855_regmap_unlock(struct an8855_core *priv)
{
	mutex_unlock(&priv->bus->mdio_lock);
	if (priv->phy_bus)
		mutex_unlock(&priv->phy_bus->mdio_lock);
}

static int an8855_regmap_read(void *ctx, uint32_t reg, uint32_t *val)
{
	struct an8855_core *priv = ctx;
	struct mii_bus *bus = priv->bus;
	u16 addr = priv->switch_addr;
	int ret;

	an8855_regmap_lock(priv);
	ret = an8855_mii_set_page(priv, addr, AN8855_PHY_PAGE_EXTENDED_4);
	if (ret < 0)
		goto exit;

	ret = an8855_mii_read32(bus, addr, reg, val);

exit:
	an8855_regmap_unlock(priv);

	return ret < 0 ? ret : 0;
}

static int an8855_mii_write32(struct mii_bus *bus, u8 phy_id, u32 reg,
			      u32 val) __must_hold(&bus->mdio_lock)
{
	int ret;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_MODE,
			      AN8855_PBUS_MODE_ADDR_FIXED);
	if (ret)
		goto err;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_WR_ADDR_HIGH,
			      upper_16_bits(reg));
	if (ret)
		goto err;
	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_WR_ADDR_LOW,
			      lower_16_bits(reg));
	if (ret)
		goto err;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_WR_DATA_HIGH,
			      upper_16_bits(val));
	if (ret)
		goto err;

	ret = __mdiobus_write(bus, phy_id, AN8855_PBUS_WR_DATA_LOW,
			      lower_16_bits(val));
	if (ret)
		goto err;

	return 0;
err:
	dev_err_ratelimited(&bus->dev,
			    "failed to write an8855 register\n");
	return ret;
}

static int an8855_regmap_write(void *ctx, uint32_t reg, uint32_t val)
{
	struct an8855_core *priv = ctx;
	struct mii_bus *bus = priv->bus;
	u16 addr = priv->switch_addr;
	int ret;

	an8855_regmap_lock(priv);
	ret = an8855_mii_set_page(priv, addr, AN8855_PHY_PAGE_EXTENDED_4);
	if (ret)
		goto exit;

	ret = an8855_mii_write32(bus, addr, reg, val);

exit:
	an8855_regmap_unlock(priv);

	return ret < 0 ? ret : 0;
}

static int an8855_regmap_update_bits(void *ctx, uint32_t reg, uint32_t mask,
				     uint32_t write_val)
{
	struct an8855_core *priv = ctx;
	struct mii_bus *bus = priv->bus;
	u16 addr = priv->switch_addr;
	u32 val;
	int ret;

	an8855_regmap_lock(priv);
	ret = an8855_mii_set_page(priv, addr, AN8855_PHY_PAGE_EXTENDED_4);
	if (ret)
		goto exit;

	ret = an8855_mii_read32(bus, addr, reg, &val);
	if (ret < 0)
		goto exit;

	val &= ~mask;
	val |= write_val & mask;
	ret = an8855_mii_write32(bus, addr, reg, val);

exit:
	an8855_regmap_unlock(priv);

	return ret < 0 ? ret : 0;
}

static const struct regmap_range an8855_readable_ranges[] = {
	regmap_reg_range(0x10000000, 0x10000fff), /* SCU */
	regmap_reg_range(0x10001000, 0x10001fff), /* RBUS */
	regmap_reg_range(0x10002000, 0x10002fff), /* MCU */
	regmap_reg_range(0x10005000, 0x10005fff), /* SYS SCU */
	regmap_reg_range(0x10007000, 0x10007fff), /* I2C Slave */
	regmap_reg_range(0x10008000, 0x10008fff), /* I2C Master */
	regmap_reg_range(0x10009000, 0x10009fff), /* PDMA */
	regmap_reg_range(0x1000a100, 0x1000a2ff), /* General Purpose Timer */
	regmap_reg_range(0x1000a200, 0x1000a2ff), /* GPU timer */
	regmap_reg_range(0x1000a300, 0x1000a3ff), /* GPIO */
	regmap_reg_range(0x1000a400, 0x1000a5ff), /* EFUSE */
	regmap_reg_range(0x1000c000, 0x1000cfff), /* GDMP CSR */
	regmap_reg_range(0x10010000, 0x1001ffff), /* GDMP SRAM */
	regmap_reg_range(0x10200000, 0x10203fff), /* Switch - ARL Global */
	regmap_reg_range(0x10204000, 0x10207fff), /* Switch - BMU */
	regmap_reg_range(0x10208000, 0x1020bfff), /* Switch - ARL Port */
	regmap_reg_range(0x1020c000, 0x1020cfff), /* Switch - SCH */
	regmap_reg_range(0x10210000, 0x10213fff), /* Switch - MAC */
	regmap_reg_range(0x10214000, 0x10217fff), /* Switch - MIB */
	regmap_reg_range(0x10218000, 0x1021bfff), /* Switch - Port Control */
	regmap_reg_range(0x1021c000, 0x1021ffff), /* Switch - TOP */
	regmap_reg_range(0x10220000, 0x1022ffff), /* SerDes */
	regmap_reg_range(0x10286000, 0x10286fff), /* RG Batcher */
	regmap_reg_range(0x1028c000, 0x1028ffff), /* ETHER_SYS */
	regmap_reg_range(0x30000000, 0x37ffffff), /* I2C EEPROM */
	regmap_reg_range(0x38000000, 0x3fffffff), /* BOOT_ROM */
	regmap_reg_range(0xa0000000, 0xbfffffff), /* GPHY */
};

static const struct regmap_access_table an8855_readable_table = {
	.yes_ranges = an8855_readable_ranges,
	.n_yes_ranges = ARRAY_SIZE(an8855_readable_ranges),
};

static const struct regmap_config an8855_regmap_config = {
	.name = "switch",
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0xbfffffff,
	.reg_read = an8855_regmap_read,
	.reg_write = an8855_regmap_write,
	.reg_update_bits = an8855_regmap_update_bits,
	.disable_locking = true,
	.rd_table = &an8855_readable_table,
};

static int an8855_regmap_phy_reset_page(struct an8855_core *priv,
					int phy) __must_hold(&priv->bus->mdio_lock)
{
	/* Check PHY page only for addr shared with switch */
	if (phy != priv->switch_addr)
		return 0;

	/* Don't restore page if it's not set to Switch page */
	if (priv->current_page != AN8855_PHY_PAGE_EXTENDED_4)
		return 0;

	/*
	 * Restore page to 0, PHY might change page right after but that
	 * will be ignored as it won't be a switch page.
	 */
	return an8855_mii_set_page(priv, phy, AN8855_PHY_PAGE_STANDARD);
}

static int an8855_regmap_phy_read(void *ctx, uint32_t reg, uint32_t *val)
{
	struct an8855_phy *priv = ctx;
	struct an8855_core *core_priv;
	u32 addr = priv->addr;
	struct mii_bus *bus;
	int ret;

	core_priv = priv->core;
	bus = core_priv->bus;

	mutex_lock_nested(&bus->mdio_lock, MDIO_MUTEX_NESTED);
	ret = an8855_regmap_phy_reset_page(core_priv, addr);
	if (ret)
		goto exit;

	ret = __mdiobus_read(bus, addr, reg);
	if (ret >= 0)
		*val = ret;

exit:
	mutex_unlock(&bus->mdio_lock);

	return ret < 0 ? ret : 0;
}

static int an8855_regmap_phy_write(void *ctx, uint32_t reg, uint32_t val)
{
	struct an8855_phy *priv = ctx;
	struct an8855_core *core_priv;
	u32 addr = priv->addr;
	struct mii_bus *bus;
	int ret;

	core_priv = priv->core;
	bus = core_priv->bus;

	mutex_lock_nested(&bus->mdio_lock, MDIO_MUTEX_NESTED);
	ret = an8855_regmap_phy_reset_page(core_priv, addr);
	if (ret)
		goto exit;

	ret = __mdiobus_write(bus, addr, reg, val);

exit:
	mutex_unlock(&bus->mdio_lock);

	return ret;
}

static const struct regmap_config an8855_phy_regmap_config = {
	.reg_bits = 16,
	.val_bits = 16,
	.reg_read = an8855_regmap_phy_read,
	.reg_write = an8855_regmap_phy_write,
	.disable_locking = true,
	.max_register = 0x1f,
};

static int an8855_read_switch_id(struct device *dev, struct regmap *regmap)
{
	u32 id;
	int ret;

	ret = regmap_read(regmap, AN8855_CREV, &id);
	if (ret)
		return ret;

	if (id != AN8855_ID) {
		dev_err(dev, "Detected Switch ID %x but %x was expected\n",
			id, AN8855_ID);
		return -ENODEV;
	}

	return 0;
}

static int an8855_phy_bus_register(struct device *dev, struct an8855_core *priv,
				   struct device_node *phy_np,
				   struct an8855_phy_bus *phy_bus_info)
{
	struct mdio_regmap_config mrc = { };
	struct an8855_phy *phy_priv;
	struct regmap *regmap;
	u32 addr, phy_offset;
	struct mii_bus *bus;
	int ret;

	ret = of_property_read_u32(phy_np, "reg", &addr);
	if (ret)
		return ret;

	phy_offset = addr - priv->switch_addr;
	if (phy_offset >= AN8855_MAX_PHY_PORT)
		return -EINVAL;

	phy_priv = devm_kzalloc(dev, sizeof(*phy_priv), GFP_KERNEL);
	if (!phy_priv)
		return -ENOMEM;

	phy_priv->addr = addr;
	phy_priv->core = priv;

	regmap = devm_regmap_init(dev, NULL, phy_priv, &an8855_phy_regmap_config);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap),
				     "phy%d regmap initialization failed\n",
				      addr);

	mrc.regmap = regmap;
	mrc.parent = dev;
	mrc.valid_addr = addr;
	snprintf(mrc.name, MII_BUS_ID_SIZE, "%s-phy%u", dev_name(dev), addr);

	bus = devm_mdio_regmap_register(dev, &mrc);
	if (IS_ERR(bus))
		return PTR_ERR(bus);

	if (addr == priv->switch_addr)
		priv->phy_bus = bus;

	phy_bus_info->bus = bus;
	phy_bus_info->addr = addr;
	phy_bus_info->node = fwnode_handle_get(of_fwnode_handle(phy_np));

	return 0;
}

static int an8855_mdio_register(struct device *dev, struct an8855_core *priv,
				struct an8855_phy_bus *phy_bus_infos)
{
	struct device_node *mdio_np;
	int ret = 0;
	int i = 0;

	mdio_np = of_get_child_by_name(dev->of_node, "mdio");
	if (!mdio_np)
		return -ENODEV;

	for_each_available_child_of_node_scoped(mdio_np, phy_np) {
		if (i >= AN8855_MAX_PHY_PORT) {
			ret = -EINVAL;
			goto exit;
		}

		ret = an8855_phy_bus_register(dev, priv, phy_np,
					      &phy_bus_infos[i]);
		if (ret)
			goto exit;

		i++;
	}

exit:
	of_node_put(mdio_np);
	if (ret) {
		while (i--)
			fwnode_handle_put(phy_bus_infos[i].node);

		return ret;
	}

	return i;
}

static int an8855_core_probe(struct mdio_device *mdiodev)
{
	struct an8855_phy_bus phy_bus_infos[AN8855_MAX_PHY_PORT] = { };
	struct device *dev = &mdiodev->dev;
	struct an8855_core *priv;
	struct regmap *regmap;
	int num_phys;
	int i, ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->bus = mdiodev->bus;
	priv->switch_addr = mdiodev->addr;
	/* No DMA for mdiobus, mute warning for DMA mask not set */
	dev->dma_mask = &dev->coherent_dma_mask;

	/* Register virtual MDIO for each PHY */
	num_phys = an8855_mdio_register(dev, priv, phy_bus_infos);
	if (num_phys < 0)
		return num_phys;

	regmap = devm_regmap_init(dev, NULL, priv, &an8855_regmap_config);
	if (IS_ERR(regmap)) {
		ret = PTR_ERR(regmap);
		dev_err_probe(dev, ret, "regmap initialization failed\n");
		goto err_put_fwnodes;
	}

	/* Reset PHY page for switch address */
	mutex_lock_nested(&priv->bus->mdio_lock, MDIO_MUTEX_NESTED);
	ret = an8855_mii_set_page(priv, priv->switch_addr,
				  AN8855_PHY_PAGE_STANDARD);
	mutex_unlock(&priv->bus->mdio_lock);
	if (ret)
		goto err_put_fwnodes;

	ret = an8855_read_switch_id(dev, regmap);
	if (ret)
		goto err_put_fwnodes;

	/* Release global PHY power down */
	ret = regmap_write(regmap, AN8855_RG_GPHY_AFE_PWD, 0x0);
	if (ret)
		goto err_put_fwnodes;

	/* Register PHYs */
	for (i = 0; i < num_phys; i++) {
		ret = fwnode_mdiobus_register_phy(phy_bus_infos[i].bus,
						  phy_bus_infos[i].node,
						  phy_bus_infos[i].addr);
		fwnode_handle_put(phy_bus_infos[i].node);
		phy_bus_infos[i].node = NULL;

		if (ret)
			goto err_put_fwnodes;
	}

	return devm_mfd_add_devices(dev, PLATFORM_DEVID_AUTO, an8855_cells,
				    ARRAY_SIZE(an8855_cells), NULL, 0,
				    NULL);

err_put_fwnodes:
	for (i = 0; i < num_phys; i++)
		if (phy_bus_infos[i].node)
			fwnode_handle_put(phy_bus_infos[i].node);

	return ret;
}

static const struct of_device_id an8855_core_of_match[] = {
	{ .compatible = "airoha,an8855" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, an8855_core_of_match);

static struct mdio_driver an8855_core_driver = {
	.probe = an8855_core_probe,
	.mdiodrv.driver = {
		.name = "an8855",
		.of_match_table = an8855_core_of_match,
	},
};
mdio_module_driver(an8855_core_driver);

MODULE_AUTHOR("Christian Marangi <ansuelsmth@gmail.com>");
MODULE_DESCRIPTION("Driver for Airoha AN8855");
MODULE_LICENSE("GPL");
