/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#ifndef __SOCE_DSA_H
#define __SOCE_DSA_H

#include <linux/mutex.h>
#include <linux/types.h>

#define SOCE_MAX_NUM_PORTS 31
#define SOCE_MAX_MDIO_ADDR 32
#define SOCE_MAX_MDIO_OUTPUTS SOCE_MAX_NUM_PORTS

struct dsa_switch;

struct soce_mdio_ops {
	int (*phy_read)(struct dsa_switch *ds, int mdio_output, int phy_addr,
			int regnum);
	int (*phy_write)(struct dsa_switch *ds, int mdio_output, int phy_addr,
			 int regnum, u16 val);
	int (*phy_read_c45)(struct dsa_switch *ds, int mdio_output, int phy_addr,
			    int devad, int regnum);
	int (*phy_write_c45)(struct dsa_switch *ds, int mdio_output, int phy_addr,
			     int devad, int regnum, u16 val);
};

struct soce_dsa_local {
	void __iomem *base_addr;
	void __iomem *mdio_master_addr;
	/* Serializes all logical buses sharing the MDIO master. */
	struct mutex mdio_lock;
	const struct soce_mdio_ops *mdio_ops;
};

struct soce_priv {
	struct soce_dsa_local local;
	struct dsa_switch *ds;
};

#endif /* __SOCE_DSA_H */
