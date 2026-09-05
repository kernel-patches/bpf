/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#ifndef __SOCE_MDIO_H
#define __SOCE_MDIO_H

#define SOCE_MDIO_CTRL_OFFSET 0x0000

/* for newer versions */
#define SOCE_MDIO_23_02_PARAMS_OFFSET		0x0004
#define SOCE_MDIO_23_02_WRITE_OFFSET		0x0008
#define SOCE_MDIO_23_02_READ_OFFSET		0x000c
#define SOCE_MDIO_23_02_CTRL_BUS_OFFSET		16
#define SOCE_MDIO_23_02_CTRL_TRANSTYPE_OFFSET	3
#define SOCE_MDIO_23_02_CTRL_CLAUSE_OFFSET	1
#define SOCE_MDIO_23_02_CTRL_OPSTATUS_OFFSET	0

#define SOCE_MDIO_23_02_CTRL_REGADDRDEVTYPE_OFFSET	8
#define SOCE_MDIO_23_02_CTRL_PHYADDR_OFFSET		0

struct device;
struct soce_priv;

int soce_mdio_23_02_read(struct dsa_switch *ds, int mdio_output, int phy_addr,
			 int regnum);
int soce_mdio_23_02_write(struct dsa_switch *ds, int mdio_output, int phy_addr,
			  int regnum, u16 val);
int soce_mdio_23_02_read_c45(struct dsa_switch *ds, int mdio_output,
			     int phy_addr, int devad, int regnum);
int soce_mdio_23_02_write_c45(struct dsa_switch *ds, int mdio_output,
			      int phy_addr, int devad, int regnum, u16 val);
int soce_sw_register_mdio_buses(struct soce_priv *priv, struct device *dev,
				u32 numports);
#endif /* __SOCE_MDIO_H */
