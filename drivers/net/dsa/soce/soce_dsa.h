/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020-2026 System on Chip engineering, S.L.
 * Copyright (c) 2026 Linutronix GmbH
 * Author: Vasilij Strassheim <v.strassheim@linutronix.de>
 */

#ifndef __SOCE_DSA_H
#define __SOCE_DSA_H

#include <linux/types.h>

#include <net/dsa.h>

#define SOCE_MAX_NUM_PORTS 31

struct soce_dsa_local {
	void __iomem *base_addr;
};

struct soce_priv {
	struct soce_dsa_local local;
	struct dsa_switch ds;
};

#endif /* __SOCE_DSA_H */
