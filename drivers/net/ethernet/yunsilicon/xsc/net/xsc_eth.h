/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ETH_H
#define __XSC_ETH_H

#include <linux/udp.h>

#include "common/xsc_core.h"
#include "xsc_eth_common.h"

struct xsc_adapter {
	struct net_device	*netdev;
	struct pci_dev		*pdev;
	struct device		*dev;
	struct xsc_core_device	*xdev;

	struct xsc_eth_params	nic_param;

	struct xsc_channel	channel;

	/* true between ndo_open and ndo_stop */
	bool			opened;
};

static inline struct net_device *xsc_dev_to_netdev(struct xsc_core_device *xdev)
{
	return ((struct xsc_adapter *)xdev->eth_priv)->netdev;
}

#endif /* __XSC_ETH_H */
