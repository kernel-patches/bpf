// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_mdio.h>
#include <linux/platform_device.h>

#define SOCE_MDIO_TIMEOUT_US		1000

#define SOCE_MDIO_PARAMS_OFFSET		0x0000
#define SOCE_MDIO_WRITE_OFFSET		0x0004
#define SOCE_MDIO_READ_OFFSET		0x0008
#define SOCE_MDIO_DATA_IOMAP_IDX	0
#define SOCE_MDIO_CTRL_IOMAP_IDX	1

#define SOCE_MDIO_CTRL_BUS_MASK		GENMASK(26, 16)
#define SOCE_MDIO_CTRL_TRANSTYPE_MASK	GENMASK(4, 3)
#define SOCE_MDIO_CTRL_TRANSTYPE_WRITE	0x1
#define SOCE_MDIO_CTRL_TRANSTYPE_READ	0x3
#define SOCE_MDIO_CTRL_CLAUSE		BIT(1)
#define SOCE_MDIO_CTRL_OPSTATUS		BIT(0)
#define SOCE_MDIO_PARAMS_REGDEV_MASK	GENMASK(12, 8)
#define SOCE_MDIO_PARAMS_PHYADDR_MASK	GENMASK(4, 0)
#define SOCE_MDIO_READ_DATA_MASK	GENMASK(15, 0)

struct soce_mdio {
	void __iomem *ctrl;
	void __iomem *data;
};

static void __iomem *soce_mdio_iomap(struct device *dev, int index)
{
	struct resource res;
	int ret;

	ret = of_address_to_resource(dev->of_node, index, &res);
	if (ret)
		return IOMEM_ERR_PTR(ret);

	return devm_ioremap(dev, res.start, resource_size(&res));
}

static int soce_mdio_wait_for_idle(struct soce_mdio *priv)
{
	void __iomem *ctrl = priv->ctrl;
	u32 val;

	return readl_poll_timeout(ctrl, val,
		!(val & SOCE_MDIO_CTRL_OPSTATUS), 10,
		SOCE_MDIO_TIMEOUT_US);
}

static void soce_mdio_start(struct soce_mdio *priv, u32 command)
{
	void __iomem *ctrl = priv->ctrl;

	/* Keep the currently selected MDIO bus while updating op bits. */
	command |= readl(ctrl) & SOCE_MDIO_CTRL_BUS_MASK;
	writel(command, ctrl);
}

static int soce_mdio_read(struct mii_bus *bus, int phy_addr, int regnum)
{
	struct soce_mdio *priv = bus->priv;
	void __iomem *data = priv->data;
	u32 command;
	int ret;

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	writel(FIELD_PREP(SOCE_MDIO_PARAMS_REGDEV_MASK, regnum) |
	       FIELD_PREP(SOCE_MDIO_PARAMS_PHYADDR_MASK, phy_addr),
	       data + SOCE_MDIO_PARAMS_OFFSET);

	command = FIELD_PREP(SOCE_MDIO_CTRL_TRANSTYPE_MASK,
			     SOCE_MDIO_CTRL_TRANSTYPE_READ) |
		  SOCE_MDIO_CTRL_OPSTATUS;
	soce_mdio_start(priv, command);

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	return readl(data + SOCE_MDIO_READ_OFFSET) & SOCE_MDIO_READ_DATA_MASK;
}

static int soce_mdio_read_c45(struct mii_bus *bus, int phy_addr, int devad,
			      int regnum)
{
	struct soce_mdio *priv = bus->priv;
	void __iomem *data = priv->data;
	u32 command;
	int ret;

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	writel(FIELD_PREP(SOCE_MDIO_PARAMS_REGDEV_MASK, devad) |
	       FIELD_PREP(SOCE_MDIO_PARAMS_PHYADDR_MASK, phy_addr),
	       data + SOCE_MDIO_PARAMS_OFFSET);
	writel(regnum, data + SOCE_MDIO_WRITE_OFFSET);

	command = SOCE_MDIO_CTRL_CLAUSE | SOCE_MDIO_CTRL_OPSTATUS;
	soce_mdio_start(priv, command);

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	command = FIELD_PREP(SOCE_MDIO_CTRL_TRANSTYPE_MASK,
			     SOCE_MDIO_CTRL_TRANSTYPE_READ) |
		  SOCE_MDIO_CTRL_CLAUSE | SOCE_MDIO_CTRL_OPSTATUS;
	soce_mdio_start(priv, command);

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	return readl(data + SOCE_MDIO_READ_OFFSET) & SOCE_MDIO_READ_DATA_MASK;
}

static int soce_mdio_write(struct mii_bus *bus, int phy_addr, int regnum,
			   u16 val)
{
	struct soce_mdio *priv = bus->priv;
	void __iomem *data = priv->data;
	u32 command;
	int ret;

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	writel(FIELD_PREP(SOCE_MDIO_PARAMS_REGDEV_MASK, regnum) |
	       FIELD_PREP(SOCE_MDIO_PARAMS_PHYADDR_MASK, phy_addr),
	       data + SOCE_MDIO_PARAMS_OFFSET);
	writel(val, data + SOCE_MDIO_WRITE_OFFSET);

	command = FIELD_PREP(SOCE_MDIO_CTRL_TRANSTYPE_MASK,
			     SOCE_MDIO_CTRL_TRANSTYPE_WRITE) |
		  SOCE_MDIO_CTRL_OPSTATUS;
	soce_mdio_start(priv, command);

	return soce_mdio_wait_for_idle(priv);
}

static int soce_mdio_write_c45(struct mii_bus *bus, int phy_addr, int devad,
			       int regnum, u16 val)
{
	struct soce_mdio *priv = bus->priv;
	void __iomem *data = priv->data;
	u32 command;
	int ret;

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	writel(FIELD_PREP(SOCE_MDIO_PARAMS_REGDEV_MASK, devad) |
	       FIELD_PREP(SOCE_MDIO_PARAMS_PHYADDR_MASK, phy_addr),
	       data + SOCE_MDIO_PARAMS_OFFSET);
	writel(regnum, data + SOCE_MDIO_WRITE_OFFSET);

	command = SOCE_MDIO_CTRL_CLAUSE | SOCE_MDIO_CTRL_OPSTATUS;
	soce_mdio_start(priv, command);

	ret = soce_mdio_wait_for_idle(priv);
	if (ret)
		return ret;

	writel(val, data + SOCE_MDIO_WRITE_OFFSET);

	command = FIELD_PREP(SOCE_MDIO_CTRL_TRANSTYPE_MASK,
			     SOCE_MDIO_CTRL_TRANSTYPE_WRITE) |
		  SOCE_MDIO_CTRL_CLAUSE | SOCE_MDIO_CTRL_OPSTATUS;
	soce_mdio_start(priv, command);

	return soce_mdio_wait_for_idle(priv);
}

static int soce_mdio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct soce_mdio *priv;
	struct mii_bus *bus;

	bus = devm_mdiobus_alloc_size(dev, sizeof(*priv));
	if (!bus)
		return -ENOMEM;

	priv = bus->priv;
	priv->data = soce_mdio_iomap(dev, SOCE_MDIO_DATA_IOMAP_IDX);
	if (IS_ERR(priv->data))
		return PTR_ERR(priv->data);

	priv->ctrl = soce_mdio_iomap(dev, SOCE_MDIO_CTRL_IOMAP_IDX);
	if (IS_ERR(priv->ctrl))
		return PTR_ERR(priv->ctrl);

	bus->name = "soce mdio";
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s", dev_name(dev));
	bus->parent = dev;
	bus->read = soce_mdio_read;
	bus->write = soce_mdio_write;
	bus->read_c45 = soce_mdio_read_c45;
	bus->write_c45 = soce_mdio_write_c45;

	return devm_of_mdiobus_register(dev, bus, dev->of_node);
}

static const struct of_device_id soce_mdio_of_match[] = {
	{ .compatible = "soce,swip-mdio-23-02" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, soce_mdio_of_match);

static struct platform_driver soce_mdio_driver = {
	.probe = soce_mdio_probe,
	.driver = {
		.name = "soce-mdio",
		.of_match_table = soce_mdio_of_match,
	},
};
module_platform_driver(soce_mdio_driver);

MODULE_AUTHOR("Vasilij Strassheim <v.strassheim@linutronix.de>");
MODULE_DESCRIPTION("SoC-e MDIO controller driver");
MODULE_LICENSE("GPL");
