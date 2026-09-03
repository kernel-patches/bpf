// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#include <linux/bits.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mdio.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>

#include <net/dsa.h>

#include "soce_dsa.h"
#include "soce_mdio.h"

#define SOCE_MDIO_TIMEOUT 1000
#define SOCE_MDIO_C22_REG_MAX 0x1f
#define SOCE_MDIO_C45_DEVAD_MAX 0x1f
#define SOCE_MDIO_C45_REG_MAX 0xffff

static inline bool soce_mdio_output_valid(int mdio_output)
{
	return mdio_output >= 0 && mdio_output < SOCE_MAX_MDIO_OUTPUTS;
}

static inline bool soce_mdio_addr_valid(int phy_addr)
{
	return phy_addr >= 0 && phy_addr < SOCE_MAX_MDIO_ADDR;
}

static inline bool soce_mdio_c22_reg_valid(int regnum)
{
	return regnum >= 0 && regnum <= SOCE_MDIO_C22_REG_MAX;
}

static inline bool soce_mdio_c45_params_valid(int devad, int regnum)
{
	return devad >= 0 && devad <= SOCE_MDIO_C45_DEVAD_MAX &&
	       regnum >= 0 && regnum <= SOCE_MDIO_C45_REG_MAX;
}

struct soce_mdio_bus {
	struct dsa_switch *ds;
	u32 mdio_output;
};

static int soce_mdio_read(struct mii_bus *bus, int addr, int reg)
{
	struct soce_mdio_bus *state = bus->priv;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	int ret;

	priv = state->ds->priv;
	local = &priv->local;

	if (!local->mdio_ops || !local->mdio_ops->phy_read)
		return -EOPNOTSUPP;

	if (!soce_mdio_addr_valid(addr))
		return -EINVAL;

	mutex_lock(&local->mdio_lock);
	ret = local->mdio_ops->phy_read(state->ds, state->mdio_output, addr,
					reg);
	mutex_unlock(&local->mdio_lock);

	return ret;
}

static int soce_mdio_write(struct mii_bus *bus, int addr, int reg, u16 val)
{
	struct soce_mdio_bus *state = bus->priv;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	int ret;

	priv = state->ds->priv;
	local = &priv->local;

	if (!local->mdio_ops || !local->mdio_ops->phy_write)
		return -EOPNOTSUPP;

	if (!soce_mdio_addr_valid(addr))
		return -EINVAL;

	mutex_lock(&local->mdio_lock);
	ret = local->mdio_ops->phy_write(state->ds, state->mdio_output, addr,
					 reg, val);
	mutex_unlock(&local->mdio_lock);

	return ret;
}

static int soce_mdio_read_c45(struct mii_bus *bus, int addr, int devad,
			      int regnum)
{
	struct soce_mdio_bus *state = bus->priv;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	int ret;

	priv = state->ds->priv;
	local = &priv->local;

	if (!local->mdio_ops || !local->mdio_ops->phy_read_c45)
		return -EOPNOTSUPP;

	if (!soce_mdio_addr_valid(addr))
		return -EINVAL;

	mutex_lock(&local->mdio_lock);
	ret = local->mdio_ops->phy_read_c45(state->ds, state->mdio_output,
					    addr, devad, regnum);
	mutex_unlock(&local->mdio_lock);

	return ret;
}

static int soce_mdio_write_c45(struct mii_bus *bus, int addr, int devad,
			       int regnum, u16 val)
{
	struct soce_mdio_bus *state = bus->priv;
	struct soce_dsa_local *local;
	struct soce_priv *priv;
	int ret;

	priv = state->ds->priv;
	local = &priv->local;

	if (!local->mdio_ops || !local->mdio_ops->phy_write_c45)
		return -EOPNOTSUPP;

	if (!soce_mdio_addr_valid(addr))
		return -EINVAL;

	mutex_lock(&local->mdio_lock);
	ret = local->mdio_ops->phy_write_c45(state->ds, state->mdio_output,
					     addr, devad, regnum, val);
	mutex_unlock(&local->mdio_lock);

	return ret;
}

static int soce_register_mdio_bus(struct soce_priv *priv, struct device *dev,
				  struct device_node *mdio_np,
				  u32 mdio_output)
{
	struct soce_mdio_bus *state;
	struct mii_bus *bus;

	bus = devm_mdiobus_alloc(dev);
	if (!bus)
		return -ENOMEM;

	state = devm_kzalloc(dev, sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->ds = priv->ds;
	state->mdio_output = mdio_output;

	bus->priv = state;
	bus->name = "soce mdio";
	bus->read = soce_mdio_read;
	bus->write = soce_mdio_write;
	bus->read_c45 = soce_mdio_read_c45;
	bus->write_c45 = soce_mdio_write_c45;
	/* ds->dst can be NULL during probe, before dsa_register_switch() */
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-mdio-%u", dev_name(dev),
		 mdio_output);
	bus->parent = dev;

	return devm_of_mdiobus_register(dev, bus, mdio_np);
}

int soce_sw_register_mdio_buses(struct soce_priv *priv, struct device *dev,
				u32 numports)
{
	struct device_node *mdios_node;
	u32 mdio_output;
	int ret = 0;

	mdios_node = of_get_child_by_name(dev->of_node, "mdios");
	if (!mdios_node)
		return 0;

	for_each_available_child_of_node_scoped(mdios_node, mdio_node) {
		ret = of_property_read_u32(mdio_node, "reg", &mdio_output);
		if (ret) {
			dev_err(dev, "missing reg in %pOF\n", mdio_node);
			goto out_put_mdio;
		}

		if (mdio_output >= numports) {
			dev_err(dev,
				"MDIO output %u in %pOF exceeds hardware limit %u\n",
				mdio_output, mdio_node, numports - 1);
			ret = -EINVAL;
			goto out_put_mdio;
		}

		ret = soce_register_mdio_bus(priv, dev, mdio_node, mdio_output);
		if (ret)
			goto out_put_mdio;
	}

out_put_mdio:
	of_node_put(mdios_node);
	return ret;
}

static int soce_mdio_23_02_wait_for_idle(struct dsa_switch *ds)
{
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;
	void __iomem *ctrl;
	u32 val;

	local = &priv->local;
	ctrl = local->mdio_master_addr + SOCE_MDIO_CTRL_OFFSET;

	return readl_poll_timeout(ctrl, val,
		!(val & (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET)), 10,
		SOCE_MDIO_TIMEOUT * 1000);
}

static int soce_mdio_23_02_read_c22(struct dsa_switch *ds, int mdio_output,
				    int phy_addr, int regnum)
{
	void __iomem *ctrl, *params, *read_reg;
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;
	u32 regvalue;
	int ret;

	local = &priv->local;
	ctrl = local->mdio_master_addr + SOCE_MDIO_CTRL_OFFSET;
	params = local->mdio_master_addr + SOCE_MDIO_23_02_PARAMS_OFFSET;
	read_reg = local->mdio_master_addr + SOCE_MDIO_23_02_READ_OFFSET;

	regvalue = (regnum << SOCE_MDIO_23_02_CTRL_REGADDRDEVTYPE_OFFSET) +
		   (phy_addr << SOCE_MDIO_23_02_CTRL_PHYADDR_OFFSET);
	writel(regvalue, params);

	regvalue = ((mdio_output << SOCE_MDIO_23_02_CTRL_BUS_OFFSET) +
		    (0x3 << SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET) +
		    (0x0 << SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET));
	writel(regvalue, ctrl);

	ret = soce_mdio_23_02_wait_for_idle(ds);
	if (ret)
		return ret;

	return readl(read_reg) & 0xffff;
}

int soce_mdio_23_02_read_c45(struct dsa_switch *ds, int mdio_output,
			     int phy_addr, int devad, int regnum)
{
	void __iomem *ctrl, *params, *read_reg, *write_reg;
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;
	u32 regvalue;
	int ret;

	if (!soce_mdio_output_valid(mdio_output) ||
	    !soce_mdio_addr_valid(phy_addr) ||
	    !soce_mdio_c45_params_valid(devad, regnum))
		return -EINVAL;

	local = &priv->local;
	ctrl = local->mdio_master_addr + SOCE_MDIO_CTRL_OFFSET;
	params = local->mdio_master_addr + SOCE_MDIO_23_02_PARAMS_OFFSET;
	write_reg = local->mdio_master_addr + SOCE_MDIO_23_02_WRITE_OFFSET;
	read_reg = local->mdio_master_addr + SOCE_MDIO_23_02_READ_OFFSET;

	regvalue = (devad << SOCE_MDIO_23_02_CTRL_REGADDRDEVTYPE_OFFSET) +
		   (phy_addr << SOCE_MDIO_23_02_CTRL_PHYADDR_OFFSET);
	writel(regvalue, params);

	writel(regnum, write_reg);

	/* address cycle */
	regvalue = ((mdio_output << SOCE_MDIO_23_02_CTRL_BUS_OFFSET) +
		    (0x0 << SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET));
	writel(regvalue, ctrl);

	ret = soce_mdio_23_02_wait_for_idle(ds);
	if (ret)
		return ret;

	/* read cycle */
	regvalue = ((mdio_output << SOCE_MDIO_23_02_CTRL_BUS_OFFSET) +
		    (0x3 << SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET));
	writel(regvalue, ctrl);

	ret = soce_mdio_23_02_wait_for_idle(ds);
	if (ret)
		return ret;

	return readl(read_reg) & 0xffff;
}

int soce_mdio_23_02_read(struct dsa_switch *ds, int mdio_output, int phy_addr,
			 int regnum)
{
	if (!soce_mdio_output_valid(mdio_output) ||
	    !soce_mdio_addr_valid(phy_addr) ||
	    !soce_mdio_c22_reg_valid(regnum))
		return -EINVAL;

	return soce_mdio_23_02_read_c22(ds, mdio_output, phy_addr, regnum);
}

static int soce_mdio_23_02_write_c22(struct dsa_switch *ds, int mdio_output,
				     int phy_addr, int regnum, u16 val)
{
	void __iomem *ctrl, *params, *write_reg;
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;
	u32 regvalue;

	local = &priv->local;
	params = local->mdio_master_addr + SOCE_MDIO_23_02_PARAMS_OFFSET;
	ctrl = local->mdio_master_addr + SOCE_MDIO_CTRL_OFFSET;
	write_reg = local->mdio_master_addr + SOCE_MDIO_23_02_WRITE_OFFSET;

	regvalue = (regnum << SOCE_MDIO_23_02_CTRL_REGADDRDEVTYPE_OFFSET) +
		   (phy_addr << SOCE_MDIO_23_02_CTRL_PHYADDR_OFFSET);
	writel(regvalue, params);

	writel(val, write_reg);

	regvalue = ((mdio_output << SOCE_MDIO_23_02_CTRL_BUS_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET) +
		    (0x0 << SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET));
	writel(regvalue, ctrl);

	return soce_mdio_23_02_wait_for_idle(ds);
}

int soce_mdio_23_02_write_c45(struct dsa_switch *ds, int mdio_output,
			      int phy_addr, int devad, int regnum, u16 val)
{
	void __iomem *ctrl, *params, *write_reg;
	struct soce_priv *priv = ds->priv;
	struct soce_dsa_local *local;
	u32 regvalue;
	int ret;

	if (!soce_mdio_output_valid(mdio_output) ||
	    !soce_mdio_addr_valid(phy_addr) ||
	    !soce_mdio_c45_params_valid(devad, regnum))
		return -EINVAL;

	local = &priv->local;
	ctrl = local->mdio_master_addr + SOCE_MDIO_CTRL_OFFSET;
	params = local->mdio_master_addr + SOCE_MDIO_23_02_PARAMS_OFFSET;
	write_reg = local->mdio_master_addr + SOCE_MDIO_23_02_WRITE_OFFSET;

	regvalue = (devad << SOCE_MDIO_23_02_CTRL_REGADDRDEVTYPE_OFFSET) +
		   (phy_addr << SOCE_MDIO_23_02_CTRL_PHYADDR_OFFSET);
	writel(regvalue, params);

	writel(regnum, write_reg);

	/* address cycle */
	regvalue = ((mdio_output << SOCE_MDIO_23_02_CTRL_BUS_OFFSET) +
		    (0x0 << SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET));
	writel(regvalue, ctrl);

	ret = soce_mdio_23_02_wait_for_idle(ds);
	if (ret)
		return ret;

	writel(val, write_reg);

	/* write cycle */
	regvalue = ((mdio_output << SOCE_MDIO_23_02_CTRL_BUS_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET) +
		    (0x1 << SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET));
	writel(regvalue, ctrl);

	return soce_mdio_23_02_wait_for_idle(ds);
}

int soce_mdio_23_02_write(struct dsa_switch *ds, int mdio_output, int phy_addr,
			  int regnum, u16 val)
{
	if (!soce_mdio_output_valid(mdio_output) ||
	    !soce_mdio_addr_valid(phy_addr) ||
	    !soce_mdio_c22_reg_valid(regnum))
		return -EINVAL;

	return soce_mdio_23_02_write_c22(ds, mdio_output, phy_addr, regnum, val);
}
